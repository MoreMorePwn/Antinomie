// SPDX-License-Identifier: GPL-3.0-only
//! Every fitted table: its last column fills the box, and every column but
//! the remainder can be dragged wider and narrower by its header divider.
use super::*;

const SPACING: f32 = 8.0;

#[test]
fn a_table_without_a_remainder_column_has_its_last_column_fill_the_box() {
    let cols = [Col::fixed(80.0), Col::flex(120.0), Col::fixed(60.0)];
    let plan = plan_with(600.0, SPACING, &cols, &[]);
    assert_eq!(plan.rest, Some(2));
    assert!(!plan.scrolls);
    assert!((plan.total - 600.0).abs() < 0.01, "{plan:?}");
    assert_eq!((plan.width(0), plan.width(1)), (80.0, 120.0));
    assert!((plan.width(2) - (600.0 - 2.0 * SPACING - 200.0)).abs() < 0.01);
    // A remainder column in the middle still takes the rest; the last one
    // keeps its width.
    let cols = [Col::fixed(80.0), Col::rest(100.0), Col::fixed(60.0)];
    let plan = plan_with(600.0, SPACING, &cols, &[]);
    assert_eq!(plan.rest, Some(1));
    assert_eq!(plan.width(2), 60.0);
    assert!((plan.total - 600.0).abs() < 0.01);
}

#[test]
fn a_tight_table_still_shrinks_its_last_column_before_scrolling() {
    let cols = [Col::fixed(200.0), Col::flex(200.0), Col::flex(200.0)];
    let plan = plan_with(400.0, SPACING, &cols, &[]);
    assert!(!plan.scrolls, "{plan:?}");
    assert!(plan.total <= 400.0 + 0.01, "{plan:?}");
    assert!(plan.width(2) >= FLEX_FLOOR);
}

#[test]
fn every_column_is_resizable_unless_it_takes_the_rest() {
    for col in [Col::fixed(80.0), Col::flex(80.0), Col::rest(80.0)] {
        assert!(col.resizable, "{col:?}");
    }
    let cols = [Col::fixed(80.0), Col::flex(120.0), Col::fixed(60.0)];
    // The dragged width of a column that is not the remainder is kept.
    let plan = plan_with(600.0, SPACING, &cols, &[Some(150.0), Some(40.0)]);
    assert_eq!(plan.width(0), 150.0);
    assert_eq!(plan.width(1), 48.0, "never below the column's floor");
    assert!(
        (plan.total - 600.0).abs() < 0.01,
        "the last column gives way"
    );
    // The last column takes the rest: a width kept for it is ignored.
    let plan = plan_with(600.0, SPACING, &cols, &[None, None, Some(10.0)]);
    assert!(plan.width(2) > 300.0, "{plan:?}");
}

/// A three-column table drawn with the builder's defaults (no
/// `resizable(true)` anywhere): its divider rects and first column width.
fn draw(ctx: &egui::Context, events: Vec<egui::Event>) -> (egui::FullOutput, f32) {
    let mut first = 0.0;
    let output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(700.0, 400.0),
            )),
            events,
            ..Default::default()
        },
        |root| {
            egui::CentralPanel::default().show(root, |ui| {
                FitBuilder::new(ui)
                    .id_salt("default-table")
                    .column(Col::fixed(120.0))
                    .column(Col::flex(160.0))
                    .column(Col::fixed(80.0))
                    .header(24.0, |mut header| {
                        header.col(|ui| {
                            head(ui, "One");
                            first = ui.max_rect().width();
                        });
                        header.col(|ui| head(ui, "Two"));
                        header.col(|ui| head(ui, "Three"));
                    })
                    .body(|body| {
                        body.rows(20.0, 3, |mut row| {
                            for text in ["a", "b", "c"] {
                                row.col(|ui| {
                                    cell(ui, Cell::Text, text);
                                });
                            }
                        });
                    });
            });
        },
    );
    (output, first)
}

#[test]
fn a_table_drawn_with_the_defaults_resizes_its_first_column_by_a_drag() {
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let (_, before) = draw(&ctx, vec![]);
    let (output, _) = draw(&ctx, vec![]);
    let one = crate::app::tests::texts(&output)
        .into_iter()
        .find(|(text, _)| text == "One")
        .expect("header")
        .1;
    // The divider sits at the right edge of the first column.
    let spacing = ctx.global_style().spacing.item_spacing.x;
    let start = egui::pos2(one.left() + before + spacing / 2.0, one.center().y);
    let mut events = vec![
        egui::Event::PointerMoved(start),
        egui::Event::PointerButton {
            pos: start,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
    ];
    let _ = draw(&ctx, std::mem::take(&mut events));
    for step in 1..=6 {
        let at = start + egui::vec2(10.0 * step as f32, 0.0);
        let _ = draw(&ctx, vec![egui::Event::PointerMoved(at)]);
    }
    let end = start + egui::vec2(60.0, 0.0);
    let _ = draw(
        &ctx,
        vec![egui::Event::PointerButton {
            pos: end,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        }],
    );
    let (_, after) = draw(&ctx, vec![]);
    assert!(
        after > before + 40.0,
        "the first column was {before} wide and is {after} after a 60 point drag"
    );
}
