// SPDX-License-Identifier: GPL-3.0-only
//! Match cards: one designed card per matched rule, with a severity stripe, a
//! short summary, a facts row and a Details button.
use super::finding::{pack_name, parse_details};
use super::*;
use crate::triage::Tone;
use antinomie_monitor_core::analysis::detection::MatchSort;

/// Widest MITRE chip list on a card; the rest is counted.
const CHIP_LIMIT: usize = 6;
/// Room between a card's title, description, facts and tags.
const CARD_GAP: f32 = 7.0;
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
    sort: MatchSort,
) -> Option<WindowKey> {
    if report.findings.is_empty() {
        return None;
    }
    if rows.is_empty() {
        ui.weak("No matches.");
        return None;
    }
    let order = sorted(report, rows, sort);
    let rows: Vec<&Vec<Cell>> = order.into_iter().map(|index| &rows[index]).collect();
    // YARA matches that say little sit folded under the ones that do.
    let (strong, weak): (Vec<&Vec<Cell>>, Vec<&Vec<Cell>>) = rows.into_iter().partition(|row| {
        finding_for(report, row).is_none_or(|finding| {
            yara_strength(report, finding) == crate::triage::family::Strength::Strong
        })
    });
    let mut opened = None;
    egui::ScrollArea::vertical()
        .id_salt("detection-matches")
        .max_height(list_height(ui))
        .auto_shrink([false, true])
        .show(ui, |ui| {
            let mut draw = |ui: &mut egui::Ui, rows: &[&Vec<Cell>], from: usize| {
                for (index, row) in rows.iter().enumerate() {
                    let row = row.as_slice();
                    let Some(finding) = finding_for(report, row) else {
                        continue;
                    };
                    if let Some(next) = card(ui, report, finding, table_id, from + index, row) {
                        opened = Some(next);
                    }
                    ui.add_space(6.0);
                }
            };
            draw(ui, &strong, 0);
            if !weak.is_empty() {
                egui::CollapsingHeader::new(
                    RichText::new(format!("Weak or generic matches ({})", weak.len()))
                        .color(theme::muted()),
                )
                .id_salt(("weak-matches", table_id))
                .default_open(strong.is_empty())
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "Unscored community rules without a family, generic or hunting \
                             rules, Elastic rules scored below 70, and rules for another \
                             platform. Nothing is removed: the counts are totals.",
                        )
                        .small()
                        .color(theme::muted()),
                    );
                    draw(ui, &weak, strong.len());
                });
            }
        });
    opened
}

/// How much a YARA match says; every other engine's match counts as strong.
pub(in crate::triage) fn yara_strength(
    report: &Report,
    finding: &Finding,
) -> crate::triage::family::Strength {
    use crate::triage::family::{strength, Strength};
    if report.engine != Engine::Yara {
        return Strength::Strong;
    }
    strength(
        &finding.title,
        &finding.severity,
        &pack_name(report, finding),
        &crate::triage::digest::yara_family(report.engine, &finding.rule_text),
    )
}

/// The least height the match list is given, however short the pane.
const MIN_LIST_HEIGHT: f32 = 240.0;

/// How tall the match list may be: what is left of the page's visible height
/// below the point it starts at, so it fills the pane and grows when the
/// Details, Activity and Jobs pane folds away. The page scrolls when the
/// list's start is lower than that.
pub(super) fn list_height(ui: &egui::Ui) -> f32 {
    // The distance from the top of the page's content, not of the screen:
    // scrolling the page must not change the list.
    let used = ui.cursor().top() - ui.min_rect().top();
    (ui.clip_rect().height() - used).max(MIN_LIST_HEIGHT)
}

/// "Sort by" and its menu, drawn inline on the row the table filter shares.
/// The choice is kept in Settings.
pub(super) fn sort_picker(ui: &mut egui::Ui, sort: &mut MatchSort) {
    {
        ui.label(RichText::new("Sort by").color(theme::muted()));
        egui::ComboBox::from_id_salt("detection-match-sort")
            .selected_text(sort.label())
            .show_ui(ui, |ui| {
                for option in MatchSort::ALL {
                    ui.selectable_value(sort, option, option.label());
                }
            })
            .response
            .on_hover_text(
                "Risk puts the highest severity first. MITRE technique sorts by the first technique id. \
                 First hit sorts by where the first hit was recorded (journal event, call or packet order); \
                 matches without a position come last.",
            );
    }
}

/// Severity on one scale: named levels and Suricata's numbers (1 is highest).
pub(super) fn risk_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" | "1" => 4,
        "medium" | "indicator" | "2" => 3,
        "low" | "3" | "4" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}

/// The digits of the first technique id as a sort key: T1055.001 is (1055, 1).
fn technique_key(finding: &Finding) -> Option<(u32, u32)> {
    finding
        .mitre
        .iter()
        .filter_map(|id| {
            let id = id.trim().trim_start_matches(['T', 't']);
            let (main, sub) = id.split_once('.').unwrap_or((id, "0"));
            Some((main.parse().ok()?, sub.parse().unwrap_or(0)))
        })
        .min()
}

/// Where the first hit was recorded: the first journal event, else the first
/// call or packet; a location with no order (bytes) has none.
fn first_hit(finding: &Finding) -> Option<u64> {
    finding
        .events
        .first()
        .copied()
        .or_else(|| match finding.evidence.first()? {
            Evidence::Call { call, .. } => Some(*call),
            Evidence::Packet { frame, .. } => Some(*frame),
            Evidence::Bytes { .. } => None,
        })
}

/// The indexes of `rows` in the order `sort` asks for; equal rows keep the
/// order the engine reported them in.
pub(super) fn sorted(report: &Report, rows: &[Vec<Cell>], sort: MatchSort) -> Vec<usize> {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    let found: Vec<Option<&Finding>> = rows.iter().map(|row| finding_for(report, row)).collect();
    order.sort_by(|a, b| {
        let (Some(x), Some(y)) = (found[*a], found[*b]) else {
            return found[*b].is_some().cmp(&found[*a].is_some());
        };
        match sort {
            MatchSort::Risk => risk_rank(&y.severity)
                .cmp(&risk_rank(&x.severity))
                .then(y.count.cmp(&x.count)),
            MatchSort::Name => x.title.to_lowercase().cmp(&y.title.to_lowercase()),
            MatchSort::Mitre => technique_key(x)
                .is_none()
                .cmp(&technique_key(y).is_none())
                .then(technique_key(x).cmp(&technique_key(y))),
            // One engine per tab: the engine's packs are the grouping left.
            MatchSort::Engine => pack_name(report, x).cmp(&pack_name(report, y)),
            MatchSort::Hits => y.count.cmp(&x.count),
            MatchSort::FirstHit => first_hit(x)
                .is_none()
                .cmp(&first_hit(y).is_none())
                .then(first_hit(x).cmp(&first_hit(y))),
        }
        .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
    });
    order
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
                    ui.label(
                        RichText::new(format!(
                            "{} {}",
                            finding.count,
                            if finding.count == 1 { "hit" } else { "hits" }
                        ))
                        .small()
                        .color(theme::muted()),
                    );
                },
                |ui| {
                    details = Some(ui.button("Details…"));
                },
            );
            ui.add_space(CARD_GAP);
            let summary = card_summary(report.engine, finding);
            clipped(ui, &summary, 2);
            ui.add_space(CARD_GAP);
            ui.add(
                egui::Label::new(
                    RichText::new(facts_line(report, finding))
                        .small()
                        .color(theme::muted()),
                )
                .wrap(),
            );
            if !finding.mitre.is_empty() {
                ui.add_space(CARD_GAP);
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

/// The rule pack (its folder or file name) and every author, in one muted
/// line. The hit count sits beside the severity tag.
fn facts_line(report: &Report, finding: &Finding) -> String {
    let mut facts = Vec::new();
    let pack = pack_name(report, finding);
    if !pack.is_empty() {
        facts.push(pack);
    }
    if !finding.author.trim().is_empty() {
        facts.push(format!("by {}", finding.author.trim()));
    }
    facts.join(" · ")
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

/// The colour role of a rule score (Elastic's 0 to 100): red (Bad) from 90,
/// orange (Elevated) from 70, amber (Warn) from 40 and muted below.
pub(crate) fn score_tone(score: u32) -> Tone {
    match score {
        90.. => Tone::Bad,
        70..=89 => Tone::Elevated,
        40..=69 => Tone::Warn,
        _ => Tone::Muted,
    }
}

/// The colour of a rule's severity tag: a named level, Suricata's priority
/// 1 to 4, or (any other whole number) a rule score.
pub(super) fn severity_color(severity: &str) -> egui::Color32 {
    theme::tone(severity_tone(severity))
}

/// The colour role of a detection's severity.
pub(super) fn severity_tone(severity: &str) -> Tone {
    let trimmed = severity.trim();
    if let Ok(score) = trimmed.parse::<u32>() {
        if score > 4 {
            return score_tone(score);
        }
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "1" | "critical" | "high" => Tone::Bad,
        "2" | "medium" | "indicator" => Tone::Warn,
        "3" | "4" | "low" | "informational" | "info" => Tone::Info,
        _ => Tone::Muted,
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
    fn rule_scores_are_coloured_by_range() {
        assert_eq!(severity_color("100"), theme::error());
        assert_eq!(severity_color("90"), theme::error());
        assert_eq!(severity_color("89"), theme::orange());
        assert_eq!(severity_color("70"), theme::orange());
        assert_eq!(severity_color("69"), theme::warn());
        assert_eq!(severity_color("50"), theme::warn());
        assert_eq!(severity_color("40"), theme::warn());
        assert_eq!(severity_color("39"), theme::muted());
        assert_eq!(severity_color("5"), theme::muted());
        assert_ne!(theme::orange(), theme::error());
        assert_ne!(theme::orange(), theme::warn());
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
        let shapes = frames(&ctx, 2, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let _ = match_cards(ui, report, TABLES[0], &view.rows[0], MatchSort::default());
            });
        });
        let joined = rendered_text(&shapes);
        assert!(joined.contains("Loader family"), "{joined}");
        assert!(joined.contains("Detects the loader stage"), "{joined}");
        assert!(joined.contains("Details…"), "{joined}");
        assert!(joined.contains("4 hits"), "{joined}");
        assert!(joined.contains("Forge Core"), "{joined}");
        assert!(joined.contains("by Ann Lee, Bob"), "{joined}");
        assert!(!joined.contains("Matched"), "{joined}");
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
        let shapes = frames(&ctx, 2, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let _ = match_cards(ui, report, TABLES[0], &view.rows[0], MatchSort::default());
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
            let output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    events,
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        if let Some(key) =
                            match_cards(ui, report, TABLES[0], &view.rows[0], MatchSort::default())
                        {
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

    fn sorting_report() -> (Report, Vec<Vec<Cell>>) {
        let mut a = finding("a", "Zeta loader", vec![bytes_at(1)]);
        a.severity = "low".into();
        a.count = 9;
        a.mitre = vec!["T1105".into()];
        let mut b = finding("b", "alpha injector", vec![bytes_at(2)]);
        b.severity = "critical".into();
        b.count = 2;
        b.mitre = vec!["T1055.001".into()];
        b.events = vec![40];
        let mut c = finding("c", "Mid runner", vec![bytes_at(3)]);
        c.severity = "medium".into();
        c.count = 5;
        c.events = vec![7];
        let mut view = View::default();
        view.results[0] = Some(Ok(report(vec![a, b, c])));
        view.rows(0);
        let Some(Ok(report)) = view.results[0].clone() else {
            unreachable!()
        };
        (report, view.rows[0].clone())
    }

    /// The match list takes the page's visible height below its start, so it
    /// grows when the Details, Activity and Jobs pane folds away (a taller
    /// pane) instead of stopping at a fixed 320 points.
    #[test]
    fn the_match_list_fills_the_pane_at_two_heights() {
        let findings: Vec<_> = (0..60)
            .map(|n| finding(&format!("r{n}"), &format!("Rule {n}"), vec![bytes_at(n)]))
            .collect();
        let mut view = View::default();
        view.results[0] = Some(Ok(report(findings)));
        view.rows(0);
        let Some(Ok(report)) = view.results[0].clone() else {
            unreachable!()
        };
        let mut lists = Vec::new();
        for height in [560.0_f32, 1000.0] {
            let ctx = egui::Context::default();
            let mut list = egui::Rect::NOTHING;
            for _ in 0..3 {
                let _ = ctx.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(900.0, height),
                        )),
                        ..Default::default()
                    },
                    |root| {
                        egui::CentralPanel::default().show(root, |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("page")
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
                                    ui.label("Matches");
                                    ui.add_space(40.0);
                                    list = ui
                                        .scope(|ui| {
                                            let _ = match_cards(
                                                ui,
                                                &report,
                                                TABLES[0],
                                                &view.rows[0],
                                                MatchSort::default(),
                                            );
                                        })
                                        .response
                                        .rect;
                                });
                        });
                    },
                );
            }
            // It ends at the bottom of the pane, give or take the panel's margin.
            assert!(list.bottom() <= height, "{list:?} in {height}");
            assert!(list.bottom() >= height - 30.0, "{list:?} in {height}");
            lists.push(list.height());
        }
        assert!(lists[0] >= MIN_LIST_HEIGHT - 1.0, "{lists:?}");
        assert!(lists[1] > lists[0] + 380.0, "{lists:?}");
        assert!(
            lists[1] > 320.0 * 2.0,
            "more than the old fixed height: {lists:?}"
        );
    }

    fn titles(report: &Report, rows: &[Vec<Cell>], sort: MatchSort) -> Vec<String> {
        sorted(report, rows, sort)
            .into_iter()
            .map(|index| finding_for(report, &rows[index]).unwrap().title.clone())
            .collect()
    }

    #[test]
    fn matches_sort_by_risk_name_technique_hits_and_first_hit() {
        let (report, rows) = sorting_report();
        assert_eq!(
            titles(&report, &rows, MatchSort::default()),
            ["alpha injector", "Mid runner", "Zeta loader"],
            "risk is the default"
        );
        assert_eq!(
            titles(&report, &rows, MatchSort::Name),
            ["alpha injector", "Mid runner", "Zeta loader"]
        );
        // T1055.001 before T1105; the one with no technique last.
        assert_eq!(
            titles(&report, &rows, MatchSort::Mitre),
            ["alpha injector", "Zeta loader", "Mid runner"]
        );
        assert_eq!(
            titles(&report, &rows, MatchSort::Hits),
            ["Zeta loader", "Mid runner", "alpha injector"]
        );
        // Journal event 7 before 40; bytes have no order and come last.
        assert_eq!(
            titles(&report, &rows, MatchSort::FirstHit),
            ["Mid runner", "alpha injector", "Zeta loader"]
        );
        assert_eq!(titles(&report, &rows, MatchSort::Engine).len(), 3);
    }

    #[test]
    fn the_sort_menu_is_drawn_and_the_order_follows_it() {
        let (report, rows) = sorting_report();
        let ctx = egui::Context::default();
        let mut sort = MatchSort::Hits;
        let shapes = frames(&ctx, 2, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                ui.horizontal(|ui| sort_picker(ui, &mut sort));
                let _ = match_cards(ui, &report, TABLES[0], &rows, sort);
            });
        });
        let mut y = std::collections::HashMap::new();
        for shape in &shapes {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                y.entry(text.to_owned()).or_insert(rect.min.y);
            });
        }
        assert!(y.contains_key("Sort by"), "{:?}", y.keys());
        assert!(y.contains_key("Hit count"), "{:?}", y.keys());
        assert!(y["Zeta loader"] < y["Mid runner"]);
        assert!(y["Mid runner"] < y["alpha injector"]);
    }

    #[test]
    fn every_author_is_shown_and_the_hits_sit_beside_the_severity() {
        let mut long = finding("long", "Long author", vec![bytes_at(1)]);
        long.author = "Florian Roth, Nasreddine Bencherchali, Someone With A Very Long Name".into();
        long.count = 3;
        let mut view = View::default();
        view.results[0] = Some(Ok(report(vec![long])));
        view.rows(0);
        let Some(Ok(report)) = &view.results[0] else {
            unreachable!()
        };
        let ctx = egui::Context::default();
        let shapes = frames(&ctx, 2, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let _ = match_cards(ui, report, TABLES[0], &view.rows[0], MatchSort::Risk);
            });
        });
        let mut at = std::collections::HashMap::new();
        for shape in &shapes {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                at.insert(text.to_owned(), rect);
            });
        }
        let joined = rendered_text(&shapes);
        assert!(
            joined.contains(
                "by Florian Roth, Nasreddine Bencherchali, Someone With A Very Long Name"
            ),
            "{joined}"
        );
        assert!(!joined.contains('…') || !joined.contains("+2"), "{joined}");
        assert!(!joined.contains("Matched"), "{joined}");
        let (badge, hits) = (&at["high"], &at["3 hits"]);
        assert!((badge.center().y - hits.center().y).abs() < 6.0);
        assert!(hits.min.x > badge.max.x, "hits are right of the severity");
    }
}
