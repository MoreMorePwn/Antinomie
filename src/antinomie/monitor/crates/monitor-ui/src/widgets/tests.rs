// SPDX-License-Identifier: GPL-3.0-only
//! The widget kit: tabs select and wrap, windows keep their title above the
//! body and close on the button, tables paint their header.
use super::*;
use eframe::egui;

const SIZE: egui::Vec2 = egui::vec2(800.0, 600.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    ctx
}

fn run(
    ctx: &egui::Context,
    events: Vec<egui::Event>,
    size: egui::Vec2,
    add: impl FnMut(&mut egui::Ui),
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events,
            ..Default::default()
        },
        add,
    )
}

fn text_rects(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
    fn walk(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(text) => {
                out.push((text.galley.text().to_owned(), text.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut out));
    out
}

fn click(
    ctx: &egui::Context,
    pos: egui::Pos2,
    size: egui::Vec2,
    add: &mut dyn FnMut(&mut egui::Ui),
) {
    for pressed in [true, false] {
        let events = vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            },
        ];
        let _ = run(ctx, events, size, &mut *add);
    }
}

#[test]
fn clicking_a_tab_selects_it_and_a_disabled_tab_stays_put() {
    let ctx = context();
    let selected = std::cell::Cell::new(0_u8);
    let mut draw = |root: &mut egui::Ui| {
        egui::CentralPanel::default().show(root, |ui| {
            let mut value = selected.get();
            tabs(
                ui,
                [
                    (0_u8, TabItem::new("Alpha")),
                    (1, TabItem::new("Beta").badge("3", Tone::Accent)),
                    (
                        2,
                        TabItem::new("Gamma").disabled("Not part of this analysis"),
                    ),
                ],
                &mut value,
            );
            selected.set(value);
        });
    };
    run(&ctx, vec![], SIZE, &mut draw);
    let output = run(&ctx, vec![], SIZE, &mut draw);
    let at = |label: &str, output: &egui::FullOutput| {
        text_rects(output)
            .into_iter()
            .find(|(text, _)| text == label)
            .unwrap()
            .1
            .center()
    };
    click(&ctx, at("Beta", &output), SIZE, &mut draw);
    assert_eq!(selected.get(), 1);
    let output = run(&ctx, vec![], SIZE, &mut draw);
    click(&ctx, at("Gamma", &output), SIZE, &mut draw);
    assert_eq!(selected.get(), 1, "a disabled tab takes no clicks");
}

#[test]
fn tabs_wrap_inside_a_narrow_pane_at_every_text_size() {
    for font in [12.0, 16.0, 24.0] {
        let ctx = context();
        crate::theme::text_size(&ctx, font);
        let width = 260.0;
        let mut selected = 0_u8;
        let mut bounds = egui::Rect::NOTHING;
        let mut output = None;
        for _ in 0..3 {
            output = Some(run(&ctx, vec![], egui::vec2(width, 500.0), |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    tabs(
                        ui,
                        [
                            "Summary",
                            "Processes",
                            "Files",
                            "A rather long section name",
                            "Network",
                        ]
                        .iter()
                        .enumerate()
                        .map(|(index, label)| {
                            (index as u8, TabItem::new(*label).badge("12", Tone::Neutral))
                        }),
                        &mut selected,
                    );
                    bounds = ui.min_rect();
                });
            }));
        }
        assert!(bounds.right() <= width + 1.0, "{font}: {bounds:?}");
        let rows: std::collections::BTreeSet<i32> = text_rects(&output.unwrap())
            .into_iter()
            .filter(|(text, _)| text != "12")
            .map(|(_, rect)| rect.center().y as i32 / 8)
            .collect();
        assert!(
            rows.len() > 1,
            "{font}: five tabs cannot fit one 260 px row"
        );
    }
}

#[test]
fn a_window_keeps_its_title_above_a_body_that_caps_its_height_and_closes_on_x() {
    let ctx = context();
    let mut open = true;
    let draw = |ctx: &egui::Context, open: &mut bool| {
        window("Probe window")
            .id(egui::Id::new("probe-window"))
            .open(open)
            .default_pos(egui::pos2(100.0, 100.0))
            .default_width(300.0)
            .show(ctx, |ui| {
                // What the Settings and New VM dialogs do.
                ui.set_max_height(300.0);
                ui.label("Body line");
            });
    };
    let mut output = None;
    for _ in 0..3 {
        output = Some(run(&ctx, vec![], SIZE, |root| {
            let ctx = &root.ctx().clone();
            draw(ctx, &mut open)
        }));
    }
    let rects = text_rects(output.as_ref().unwrap());
    let title = rects
        .iter()
        .find(|(text, _)| text == "Probe window")
        .unwrap()
        .1;
    let body = rects
        .iter()
        .find(|(text, _)| text == "Body line")
        .unwrap()
        .1;
    assert!(
        title.bottom() <= body.top() + 1.0,
        "{title:?} over {body:?}"
    );
    // The title sits at the left; the close button at the right edge.
    let area = ctx
        .memory(|memory| memory.area_rect(egui::Id::new("probe-window")))
        .unwrap();
    assert!(title.left() < area.left() + 40.0, "{title:?} in {area:?}");
    // The window does not grow from one frame to the next.
    let again = run(&ctx, vec![], SIZE, |root| {
        let ctx = &root.ctx().clone();
        draw(ctx, &mut open)
    });
    drop(again);
    let later = ctx
        .memory(|memory| memory.area_rect(egui::Id::new("probe-window")))
        .unwrap();
    assert_eq!(area.size(), later.size());
    // Clicking the close button closes it.
    let pos = egui::pos2(area.right() - 11.0 - 16.0, title.center().y);
    let mut draw_once = |root: &mut egui::Ui| draw(&root.ctx().clone(), &mut open);
    click(&ctx, pos, SIZE, &mut draw_once);
    assert!(!open, "the close button must clear `open`");
}

#[test]
fn chips_and_tones_use_the_active_theme() {
    for theme in crate::theme::Theme::ALL {
        let ctx = context();
        crate::theme::apply_theme(&ctx, theme);
        for tone in Tone::ALL {
            assert_ne!(tone.fg(), tone.bg());
            assert!(tone.bg().a() < 255, "{tone:?} tint must be translucent");
        }
        assert_eq!(Tone::Good.fg(), theme.palette().good);
        assert_eq!(Tone::Live.fg(), theme.palette().live);
    }
}

#[test]
fn toggle_chips_show_their_state_and_count_and_segmented_shows_badges() {
    let ctx = context();
    let mut selected = 0;
    let mut out = egui::FullOutput::default();
    for n in 0..3 {
        out = run(&ctx, vec![], SIZE, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                toggle_chip(ui, "Hide stdio", true, None);
                toggle_chip(ui, "Failed attempts", false, Some(2));
                segmented(
                    ui,
                    [
                        (0, TabItem::new("Tree").badge("5", Tone::Neutral)),
                        (1, TabItem::new("Suspicious").badge("3", Tone::Warn)),
                    ],
                    &mut selected,
                );
            });
        });
        let _ = n;
    }
    let shown = text_rects(&out);
    assert!(shown.iter().any(|(text, _)| text.ends_with("Hide stdio")));
    assert!(shown.iter().any(|(text, _)| text == "Failed attempts 2"));
    assert!(shown.iter().any(|(text, _)| text == "Tree5"));
    assert!(shown.iter().any(|(text, _)| text == "Suspicious3"));
}

#[test]
fn a_card_shows_its_title_header_and_body_inside_the_width_it_is_given() {
    let ctx = context();
    let size = egui::vec2(600.0, 300.0);
    let mut output = None;
    for _ in 0..3 {
        output = Some(run(&ctx, vec![], size, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                card(
                    ui,
                    "Identity",
                    |ui| {
                        ui.label("link");
                    },
                    |ui| {
                        ui.label("body text");
                    },
                );
            });
        }));
    }
    let shown = text_rects(&output.unwrap());
    let rect = |label: &str| shown.iter().find(|(text, _)| text == label).unwrap().1;
    assert!(
        rect("Identity").min.x < rect("link").min.x,
        "the header sits at the right"
    );
    assert!(rect("body text").min.y > rect("Identity").max.y);
    assert!(rect("link").max.x <= size.x);
}

fn vertical_lines(output: &egui::FullOutput) -> Vec<(f32, f32, f32)> {
    fn walk(shape: &egui::Shape, out: &mut Vec<(f32, f32, f32)>) {
        match shape {
            egui::Shape::LineSegment { points, stroke } if points[0].x == points[1].x => {
                out.push((points[0].x, (points[1].y - points[0].y).abs(), stroke.width))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut out));
    out
}

#[test]
fn a_column_divider_is_one_physical_pixel_wide_on_a_pixel_centre_in_both_themes() {
    use crate::theme::Theme;
    for theme in Theme::ALL {
        for ppp in [1.0_f32, 1.5, 2.0] {
            let ctx = context();
            crate::theme::apply_theme(&ctx, theme);
            ctx.set_pixels_per_point(ppp);
            let mut table = |ui: &mut egui::Ui| {
                fit_table::FitBuilder::new(ui)
                    .id_salt("divider-table")
                    .resizable(true)
                    .column(fit_table::Col::fixed(100.0))
                    .column(fit_table::Col::rest(100.0))
                    .header(20.0, |mut header| {
                        header.col(|ui| fit_table::head(ui, "One"));
                        header.col(|ui| fit_table::head(ui, "Two"));
                    })
                    .body(|body| {
                        body.rows(18.0, 3, |mut row| {
                            row.col(|ui| {
                                ui.label("a");
                            });
                            row.col(|ui| {
                                ui.label("b");
                            });
                        })
                    });
            };
            let _ = run(&ctx, vec![], SIZE, &mut table);
            let mut output = run(&ctx, vec![], SIZE, &mut table);
            let one = text_rects(&output)
                .into_iter()
                .find(|(text, _)| text == "One")
                .unwrap()
                .1;
            let at = egui::pos2(one.left() + 100.0 + 4.0, one.center().y);
            for _ in 0..3 {
                output = run(&ctx, vec![egui::Event::PointerMoved(at)], SIZE, &mut table);
            }
            let lines: Vec<_> = vertical_lines(&output)
                .into_iter()
                .filter(|(_, length, _)| (*length - 20.0).abs() < 1.0)
                .collect();
            assert!(!lines.is_empty(), "no divider while hovered: {lines:?}");
            for (x, _, width) in lines {
                assert!(
                    (width - 1.0 / ppp).abs() < 1e-4,
                    "{theme:?} {ppp}: {width} wide"
                );
                let pixel = x * ppp;
                assert!(
                    (pixel - pixel.floor() - 0.5).abs() < 1e-3,
                    "{theme:?} {ppp}: x {x} is not a pixel centre"
                );
            }
        }
    }
}

#[test]
fn the_empty_state_panel_sits_in_the_middle_of_its_pane_on_both_axes() {
    let ctx = context();
    let size = egui::vec2(900.0, 700.0);
    let mut bounds = egui::Rect::NOTHING;
    let mut output = None;
    for _ in 0..4 {
        output = Some(run(&ctx, vec![], size, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                let room = ui.available_rect_before_wrap();
                info_panel(
                    ui,
                    &InfoPanel {
                        icon: "i",
                        title: "Select a run to view its details",
                        about: "Details show a run's recorded process tree, analysis checklist, \
                                route and recording status.",
                        steps_title: "To see a run",
                        steps: &["Select a run in Run History."],
                    },
                );
                bounds = room;
            });
        }));
    }
    let texts = text_rects(&output.unwrap());
    let all = texts
        .iter()
        .fold(egui::Rect::NOTHING, |all, (_, rect)| all.union(*rect));
    let title = texts
        .iter()
        .find(|(text, _)| text == "Select a run to view its details")
        .unwrap()
        .1;
    assert!(
        (all.center().y - bounds.center().y).abs() < 14.0,
        "vertical: content {all:?} in {bounds:?}"
    );
    assert!(
        (title.center().x - bounds.center().x).abs() < 2.0,
        "horizontal: title {title:?} in {bounds:?}"
    );
}

fn filled_rects(output: &egui::FullOutput) -> Vec<(egui::Rect, egui::Color32)> {
    fn walk(shape: &egui::Shape, out: &mut Vec<(egui::Rect, egui::Color32)>) {
        match shape {
            egui::Shape::Rect(rect) if rect.fill != egui::Color32::TRANSPARENT => {
                out.push((rect.rect, rect.fill))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut out));
    out
}

fn horizontal_lines(output: &egui::FullOutput) -> Vec<(f32, f32, egui::Stroke)> {
    fn walk(shape: &egui::Shape, out: &mut Vec<(f32, f32, egui::Stroke)>) {
        match shape {
            egui::Shape::LineSegment { points, stroke } if points[0].y == points[1].y => {
                out.push((points[0].y, (points[1].x - points[0].x).abs(), *stroke))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut out));
    out
}

/// The column divider and the header's row rule are one stroke, and the header
/// cells share pixel-aligned edges, so no seam shows between two of them.
#[test]
fn column_lines_match_the_row_rule_and_cells_leave_no_seam() {
    for ppp in [1.0_f32, 1.25, 1.5, 2.0] {
        let ctx = context();
        ctx.set_pixels_per_point(ppp);
        let mut table = |ui: &mut egui::Ui| {
            fit_table::FitBuilder::new(ui)
                .id_salt("seam-table")
                .resizable(true)
                .column(fit_table::Col::fixed(101.3))
                .column(fit_table::Col::fixed(77.7))
                .column(fit_table::Col::rest(100.0))
                .header(20.0, |mut header| {
                    for name in ["One", "Two", "Three"] {
                        header.col(|ui| fit_table::head(ui, name));
                    }
                })
                .body(|body| {
                    body.rows(18.0, 2, |mut row| {
                        for _ in 0..3 {
                            row.col(|ui| {
                                ui.label("a");
                            });
                        }
                    })
                });
        };
        let _ = run(&ctx, vec![], SIZE, &mut table);
        let mut output = run(&ctx, vec![], SIZE, &mut table);
        let one = text_rects(&output)
            .into_iter()
            .find(|(text, _)| text == "One")
            .unwrap()
            .1;
        let at = egui::pos2(one.left() + 101.3 + 4.0, one.center().y);
        for _ in 0..3 {
            output = run(&ctx, vec![egui::Event::PointerMoved(at)], SIZE, &mut table);
        }
        // The header fills sit on whole pixels, so neighbours abut exactly.
        let panel = crate::theme::panel();
        for (rect, fill) in filled_rects(&output) {
            if fill != panel || (rect.height() - 20.0).abs() > 3.0 {
                continue;
            }
            for edge in [rect.min.x, rect.max.x, rect.min.y, rect.max.y] {
                let pixel = edge * ppp;
                assert!(
                    (pixel - pixel.round()).abs() < 1e-3,
                    "{ppp}: header fill edge {edge} is between pixels ({rect:?})"
                );
            }
        }
        // The divider and the row rule are the same stroke.
        let divider = vertical_lines(&output)
            .into_iter()
            .find(|(_, length, _)| (*length - 20.0).abs() < 1.0)
            .expect("a divider while hovered");
        let rule = horizontal_lines(&output)
            .into_iter()
            .find(|(_, length, _)| *length > 50.0)
            .expect("the header rule");
        assert!(
            (divider.2 - 1.0 / ppp).abs() < 1e-4 && (rule.2.width - divider.2).abs() < 1e-4,
            "{ppp}: divider {} wide, rule {} wide",
            divider.2,
            rule.2.width
        );
        fn line_strokes(shape: &egui::Shape, out: &mut Vec<egui::Color32>) {
            match shape {
                egui::Shape::LineSegment { stroke, .. } => out.push(stroke.color),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| line_strokes(s, out)),
                _ => {}
            }
        }
        let mut colours = Vec::new();
        output
            .shapes
            .iter()
            .for_each(|clipped| line_strokes(&clipped.shape, &mut colours));
        let found = colours
            .iter()
            .filter(|colour| **colour == crate::theme::line())
            .count()
            >= 2;
        assert!(
            found,
            "{ppp}: the divider and the rule share the line colour"
        );
    }
}

fn circles(output: &egui::FullOutput) -> Vec<(egui::Pos2, f32, egui::Color32)> {
    fn walk(shape: &egui::Shape, out: &mut Vec<(egui::Pos2, f32, egui::Color32)>) {
        match shape {
            egui::Shape::Circle(circle) => out.push((circle.center, circle.radius, circle.fill)),
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| walk(shape, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    output
        .shapes
        .iter()
        .for_each(|clipped| walk(&clipped.shape, &mut out));
    out
}

/// The MITRE ATT&CK list (Triage > Summary) draws its technique rows with
/// these badges: the tactic's dot is drawn on the middle of the text, not
/// typed as a glyph that sits on the font's own box.
#[test]
fn a_mitre_row_draws_its_tactic_dot_on_the_middle_of_its_text() {
    for ppp in [1.0_f32, 1.5, 2.0] {
        let ctx = context();
        ctx.set_pixels_per_point(ppp);
        let mut draw = |ui: &mut egui::Ui| {
            attack::technique_row(ui, "test", "T1059.004", None, "2 rules", |_| {});
            attack::tactic_heading(
                ui,
                Some(antinomie_monitor_core::mitre::Tactic::Execution),
                1,
            );
        };
        let _ = run(&ctx, vec![], SIZE, &mut draw);
        let output = run(&ctx, vec![], SIZE, &mut draw);
        assert!(
            !text_rects(&output)
                .iter()
                .any(|(text, _)| text.contains('●')),
            "{ppp}: a typed dot is left"
        );
        let id = text_rects(&output)
            .into_iter()
            .find(|(text, _)| text == "T1059.004" || text.starts_with("T1059.004"))
            .expect("the technique id")
            .1;
        let dots: Vec<_> = circles(&output)
            .into_iter()
            .filter(|(centre, _, _)| (centre.y - id.center().y).abs() < 8.0)
            .collect();
        assert!(!dots.is_empty(), "{ppp}: no dot beside the id {id:?}");
        for (centre, radius, _) in dots {
            assert!(
                centre.x < id.left() && radius >= 2.0,
                "{ppp}: dot {centre:?} r{radius} is not before the text {id:?}"
            );
            // The middle of the lowercase letters and capitals, not the box.
            assert!(
                (centre.y - id.center().y).abs() <= 2.0,
                "{ppp}: dot at {} but the text's middle is {}",
                centre.y,
                id.center().y
            );
        }
        // Room between the dots and before the text.
        let mut row: Vec<_> = circles(&output)
            .into_iter()
            .filter(|(centre, _, _)| (centre.y - id.center().y).abs() < 8.0 && centre.x < id.left())
            .collect();
        row.sort_by(|a, b| a.0.x.total_cmp(&b.0.x));
        let last = row.last().unwrap();
        assert!(
            id.left() - (last.0.x + last.1) >= 4.0,
            "{ppp}: the last dot touches the id"
        );
        for pair in row.windows(2) {
            assert!(
                pair[1].0.x - pair[1].1 - (pair[0].0.x + pair[0].1) >= 4.0,
                "{ppp}: two dots are too close"
            );
        }
    }
}

fn key(key: egui::Key) -> Vec<egui::Event> {
    vec![egui::Event::Key {
        key,
        physical_key: Some(key),
        pressed: true,
        repeat: false,
        modifiers: egui::Modifiers::NONE,
    }]
}

#[test]
fn a_filter_box_shows_its_cross_only_with_text_and_the_cross_and_esc_clear_it() {
    let ctx = context();
    let size = egui::vec2(500.0, 120.0);
    let text = std::cell::RefCell::new(String::new());
    let mut draw = |root: &mut egui::Ui| {
        egui::CentralPanel::default().show(root, |ui| {
            let mut value = text.borrow_mut();
            let edit = ui.add(
                egui::TextEdit::singleline(&mut *value)
                    .hint_text("Filter")
                    .margin(clear_margin(crate::theme::TEXT_EDIT_MARGIN))
                    .desired_width(300.0),
            );
            clear_button(ui, &edit, &mut value);
        });
    };
    let cross = cross_glyph();
    let shown = |output: &egui::FullOutput| text_rects(output).into_iter().any(|(t, _)| t == cross);
    run(&ctx, vec![], size, &mut draw);
    let output = run(&ctx, vec![], size, &mut draw);
    assert!(!shown(&output), "an empty box has no cross");
    // Typed text brings the cross.
    *text.borrow_mut() = "evil".into();
    let output = run(&ctx, vec![], size, &mut draw);
    assert!(shown(&output), "a box with text has a cross");
    let at = text_rects(&output)
        .into_iter()
        .find(|(t, _)| *t == cross)
        .unwrap()
        .1
        .center();
    // The cross sits inside the box's right edge.
    assert!(at.x > 250.0 && at.x < 330.0, "{at:?}");
    click(&ctx, at, size, &mut draw);
    assert_eq!(*text.borrow(), "");
    let output = run(&ctx, vec![], size, &mut draw);
    assert!(!shown(&output));
    // Esc in the focused box clears it too.
    *text.borrow_mut() = "again".into();
    let output = run(&ctx, vec![], size, &mut draw);
    let hint_at = egui::pos2(100.0, at.y);
    click(&ctx, hint_at, size, &mut draw);
    let _ = output;
    run(&ctx, vec![], size, &mut draw);
    run(&ctx, key(egui::Key::Escape), size, &mut draw);
    assert_eq!(*text.borrow(), "", "Esc cleared the focused box");
}

fn cross_glyph() -> &'static str {
    egui_phosphor::regular::X
}

#[test]
fn a_window_never_takes_more_than_four_fifths_of_the_area_whatever_its_content() {
    for size in [egui::vec2(1400.0, 900.0), egui::vec2(700.0, 500.0)] {
        let ctx = context();
        let long = "word ".repeat(1000);
        let mut rect = egui::Rect::NOTHING;
        for _ in 0..6 {
            run(&ctx, vec![], size, |root| {
                let ctx = root.ctx().clone();
                let shown = window("A wide window")
                    .id(egui::Id::new("wide"))
                    .show(&ctx, |ui| {
                        // Long wrapped text above a long list in its own scroll area.
                        ui.add(egui::Label::new(long.as_str()).wrap());
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            for line in 0..200 {
                                ui.label(format!("line {line}"));
                            }
                        });
                    });
                if let Some(shown) = shown {
                    rect = shown.response.rect;
                }
            });
        }
        let area = crate::title_bar::content_rect(&ctx);
        assert!(
            rect.width() <= area.width() * 0.8 + 1.0,
            "{rect:?} in {area:?}"
        );
        // egui does not clip a window's content to its height: a body caps
        // its own list with a scroll area (the rules window does); the
        // width is what the window itself holds.
        assert!(rect.width() >= 280.0, "{rect:?}");
    }
}
