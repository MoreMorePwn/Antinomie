// SPDX-License-Identifier: GPL-3.0-only
//! The help icon: its text's blocks, hover and click, a disabled row, the
//! width cap, and a control drawn with its icon beside it.
use super::*;
use eframe::egui;

const SIZE: egui::Vec2 = egui::vec2(900.0, 600.0);

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    ctx.all_styles_mut(|style| style.interaction.tooltip_delay = 0.0);
    ctx
}

fn frame(
    ctx: &egui::Context,
    events: Vec<egui::Event>,
    add: &mut dyn FnMut(&mut egui::Ui),
) -> egui::FullOutput {
    ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| add(ui));
        },
    )
}

fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
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
    for clipped in &output.shapes {
        walk(&clipped.shape, &mut out);
    }
    out
}

fn icon(output: &egui::FullOutput) -> egui::Rect {
    texts(output)
        .into_iter()
        .find(|(text, _)| text == egui_phosphor::regular::QUESTION)
        .expect("a help icon")
        .1
}

fn hover(
    ctx: &egui::Context,
    pos: egui::Pos2,
    add: &mut dyn FnMut(&mut egui::Ui),
) -> egui::FullOutput {
    let mut output = frame(ctx, vec![], add);
    for _ in 0..6 {
        output = frame(ctx, vec![egui::Event::PointerMoved(pos)], add);
    }
    output
}

fn click(ctx: &egui::Context, pos: egui::Pos2, add: &mut dyn FnMut(&mut egui::Ui)) {
    for pressed in [true, false] {
        frame(
            ctx,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            add,
        );
    }
}

const TEXT: &str = "Saved hits per rule\n\nHow many hits of one rule a scan keeps, with `16` the least.\n\n- Raise it to keep more.\n- Scan again after.";

#[test]
fn a_help_text_has_a_title_paragraphs_and_bullets() {
    assert_eq!(
        blocks(TEXT),
        vec![
            Block::Title("Saved hits per rule".into()),
            Block::Paragraph("How many hits of one rule a scan keeps, with `16` the least.".into()),
            Block::Bullet("Raise it to keep more.".into()),
            Block::Bullet("Scan again after.".into()),
        ]
    );
    // One line: a short first sentence is the title, an abbreviation is not
    // a sentence end, and a text of one sentence has no title.
    assert_eq!(
        blocks("Quit gdb, e.g. after a crash. The process keeps running."),
        vec![
            Block::Title("Quit gdb, e.g. after a crash.".into()),
            Block::Paragraph("The process keeps running.".into()),
        ]
    );
    assert_eq!(
        blocks("Quit gdb; the process keeps running"),
        vec![Block::Paragraph(
            "Quit gdb; the process keeps running".into()
        )]
    );
    // A long first sentence is no title; a long text still gets a break
    // after it.
    let long = format!("{}. And more.", "word ".repeat(20).trim());
    assert!(matches!(blocks(&long)[..], [Block::Paragraph(_)]));
    let longer = format!(
        "{}. {}",
        "word ".repeat(20).trim(),
        "More words here. ".repeat(6)
    );
    assert!(matches!(
        blocks(&longer)[..],
        [Block::Paragraph(_), Block::Paragraph(_)]
    ));
    // A bullet's second line runs on; lines of a paragraph join.
    assert_eq!(
        blocks("Title\n\nFirst line\nsecond line\n- item\n  goes on"),
        vec![
            Block::Title("Title".into()),
            Block::Paragraph("First line second line".into()),
            Block::Bullet("item goes on".into()),
        ]
    );
}

#[test]
fn hovering_or_clicking_the_icon_shows_the_formatted_text_capped_in_width() {
    let ctx = context();
    let long = format!(
        "Title line\n\n{}",
        "A long paragraph that must wrap. ".repeat(20)
    );
    let mut draw = |ui: &mut egui::Ui| {
        help(ui, &long);
    };
    let at = icon(&frame(&ctx, vec![], &mut draw));
    let shown = texts(&hover(&ctx, at.center(), &mut draw));
    let title = shown
        .iter()
        .find(|(text, _)| text == "Title line")
        .expect("the title on hover");
    let paragraph = shown
        .iter()
        .find(|(text, _)| text.starts_with("A long paragraph"))
        .expect("the paragraph on hover");
    assert!(
        paragraph.1.top() - title.1.bottom() > 6.0,
        "a blank line between title and paragraph: {title:?} {paragraph:?}"
    );
    assert!(
        paragraph.1.width() <= HELP_WIDTH + 1.0,
        "wrapped at the cap: {}",
        paragraph.1.width()
    );
    assert!(
        paragraph.1.height() > 3.0 * title.1.height(),
        "several lines"
    );

    // Away from the icon: nothing. A click pins it until a click elsewhere.
    let away = egui::pos2(600.0, 500.0);
    let shown = texts(&hover(&ctx, away, &mut draw));
    assert!(!shown.iter().any(|(text, _)| text == "Title line"));
    click(&ctx, at.center(), &mut draw);
    let shown = texts(&hover(&ctx, away, &mut draw));
    assert!(
        shown.iter().any(|(text, _)| text == "Title line"),
        "pinned by the click: {shown:?}"
    );
    click(&ctx, away, &mut draw);
    let shown = texts(&hover(&ctx, away, &mut draw));
    assert!(
        !shown.iter().any(|(text, _)| text == "Title line"),
        "closed"
    );
}

#[test]
fn the_icon_of_a_disabled_row_still_shows_its_text_on_hover_and_click() {
    let ctx = context();
    let mut draw = |ui: &mut egui::Ui| {
        ui.add_enabled_ui(false, |ui| {
            let mut on = true;
            with_help(ui, "Why this box matters. It is read-only now.", |ui| {
                ui.checkbox(&mut on, "Randomize serials")
            });
        });
    };
    let first = frame(&ctx, vec![], &mut draw);
    let at = icon(&first);
    let boxed = texts(&first)
        .into_iter()
        .find(|(text, _)| text == "Randomize serials")
        .unwrap()
        .1;
    assert!((at.center().y - boxed.center().y).abs() < 6.0 && at.left() > boxed.right());
    let shown = texts(&hover(&ctx, at.center(), &mut draw));
    assert!(
        shown
            .iter()
            .any(|(text, _)| text == "Why this box matters."),
        "{shown:?}"
    );
    let away = egui::pos2(600.0, 500.0);
    click(&ctx, at.center(), &mut draw);
    let shown = texts(&hover(&ctx, away, &mut draw));
    assert!(
        shown.iter().any(|(text, _)| text == "It is read-only now."),
        "pinned on a disabled row: {shown:?}"
    );
}

#[test]
fn a_disabled_control_leads_its_icon_with_the_reason() {
    let ctx = context();
    let enabled = std::cell::Cell::new(false);
    let mut draw = |ui: &mut egui::Ui| {
        with_help_or(ui, "Reads the archive back.", "Start the VM first", |ui| {
            ui.add_enabled(enabled.get(), egui::Button::new("Verify"))
        });
    };
    let at = icon(&frame(&ctx, vec![], &mut draw));
    let shown = texts(&hover(&ctx, at.center(), &mut draw));
    assert!(
        shown.iter().any(|(text, _)| text == "Start the VM first"),
        "{shown:?}"
    );
    assert!(shown
        .iter()
        .any(|(text, _)| text == "Reads the archive back."));
    enabled.set(true);
    let shown = texts(&hover(&ctx, at.center(), &mut draw));
    assert!(
        !shown.iter().any(|(text, _)| text == "Start the VM first"),
        "{shown:?}"
    );
    assert!(shown
        .iter()
        .any(|(text, _)| text == "Reads the archive back."));
}

#[test]
fn a_name_is_one_to_four_short_words() {
    assert!(is_name("Refresh"));
    assert!(is_name("Open in a pane"));
    assert!(!is_name("Open this category in a separate pane"));
    assert!(!is_name(&"x".repeat(NAME_CHARS + 1)));
}
