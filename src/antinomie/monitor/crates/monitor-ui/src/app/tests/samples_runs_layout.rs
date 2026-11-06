// SPDX-License-Identifier: GPL-3.0-only
//! The sample window's Runs list: its columns keep a width their content needs.
use super::samples_detail::{until, window};
use super::*;

/// The width of each header's cell (the clip of its text), left to right, at a
/// window `width` wide.
fn header_cells(app: &mut MonitorApp, ctx: &egui::Context, width: f32) -> Vec<(&'static str, f32)> {
    let size = egui::vec2(width, 820.0);
    for _ in 0..4 {
        render(app, ctx, size);
    }
    let output = render(app, ctx, size);
    let mut cells = Vec::new();
    for clipped in &output.shapes {
        galleys(&clipped.shape, &mut |text, _| {
            if ["Arguments", "Tree status", "Root exit", "VM"].contains(&text)
                && clipped.clip_rect.top() > 100.0
            {
                cells.push((text.to_owned(), clipped.clip_rect));
            }
        });
    }
    ["Arguments", "Tree status", "Root exit", "VM"]
        .into_iter()
        .map(|name| {
            let (_, clip) = cells
                .iter()
                .find(|(text, _)| text == name)
                .unwrap_or_else(|| panic!("no {name} header in {cells:?}"));
            (name, clip.width())
        })
        .collect()
}

#[test]
fn the_runs_columns_keep_a_width_their_content_needs() {
    let (mut app, ctx, _, root) = window("runs-columns");
    until(&mut app, &ctx, |app| {
        app.samples_page.detail_probe().is_some()
    });
    app.samples_page.show_detail_tab("runs");
    let least = crate::app::samples_page::SamplesPage::run_column_minimums();
    for width in [1900.0, 1400.0, 1100.0] {
        let cells = header_cells(&mut app, &ctx, width);
        for (at, (name, wide)) in cells.iter().enumerate() {
            assert!(
                *wide >= least[at] - 1.0,
                "width {width}: {name} is {wide} wide, wants {}",
                least[at]
            );
        }
        if width > 1800.0 {
            // Arguments is the column that takes the spare width.
            assert!(cells[0].1 > least[0] + 30.0, "{cells:?}");
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

fn galleys(shape: &egui::Shape, found: &mut impl FnMut(&str, egui::Rect)) {
    match shape {
        egui::Shape::Text(text) => found(text.galley.text(), text.visual_bounding_rect()),
        egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| galleys(shape, found)),
        _ => {}
    }
}
