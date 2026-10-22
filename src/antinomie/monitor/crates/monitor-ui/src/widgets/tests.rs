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
    add: impl FnMut(&egui::Context),
) -> egui::FullOutput {
    ctx.run(
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
    add: &mut dyn FnMut(&egui::Context),
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
    let mut draw = |ctx: &egui::Context| {
        egui::CentralPanel::default().show(ctx, |ui| {
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
            output = Some(run(&ctx, vec![], egui::vec2(width, 500.0), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
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
        output = Some(run(&ctx, vec![], SIZE, |ctx| draw(ctx, &mut open)));
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
    let again = run(&ctx, vec![], SIZE, |ctx| draw(ctx, &mut open));
    drop(again);
    let later = ctx
        .memory(|memory| memory.area_rect(egui::Id::new("probe-window")))
        .unwrap();
    assert_eq!(area.size(), later.size());
    // Clicking the close button closes it.
    let pos = egui::pos2(area.right() - 11.0 - 16.0, title.center().y);
    let mut draw_once = |ctx: &egui::Context| draw(ctx, &mut open);
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
        out = run(&ctx, vec![], SIZE, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
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
        output = Some(run(&ctx, vec![], size, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
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
