// SPDX-License-Identifier: MIT
//! Click-to-sort for plain tables: the header cell and the row order it picks.
//! The header and its arrow are the triage tables' own (`triage::sort_header`);
//! this adds the ordering for tables that hold ordinary Rust rows.
use crate::triage::{sort_current, sort_header};
use eframe::egui;
use std::cmp::Ordering;

/// A sortable header cell. A first click sorts ascending, the next one
/// descending; right-click offers the recorded order.
pub(crate) fn header(ui: &mut egui::Ui, table: &str, column: usize, title: &str) {
    sort_header(ui, table, column, title);
}

/// `header` for a numeric column: the label sits at the right edge, like the
/// column's cells.
pub(crate) fn header_aligned(
    ui: &mut egui::Ui,
    table: &str,
    column: usize,
    title: &str,
    align: egui::Align,
) {
    crate::widgets::table::aligned(ui, align, |ui| header(ui, table, column, title));
}

/// Row indices in the order the table's header clicks chose; `0..len` while
/// none did. `compare(column, a, b)` orders rows `a` and `b` ascending and the
/// result is reversed for a descending sort. Equal rows keep their order.
pub(crate) fn order(
    ctx: &egui::Context,
    table: &str,
    len: usize,
    compare: impl Fn(usize, usize, usize) -> Ordering,
) -> Vec<usize> {
    let mut rows: Vec<usize> = (0..len).collect();
    if let Some(spec) = sort_current(ctx, table) {
        rows.sort_by(|&a, &b| {
            let order = compare(spec.column, a, b);
            if spec.descending {
                order.reverse()
            } else {
                order
            }
        });
    }
    rows
}

/// Drawing and clicking helpers for tests of sortable tables.
#[cfg(test)]
pub(crate) mod testing {
    use eframe::egui;

    fn collect(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
        match shape {
            egui::Shape::Text(text) => {
                out.push((text.galley.text().to_owned(), text.visual_bounding_rect()))
            }
            egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
            _ => {}
        }
    }

    /// One frame of `show` with `events`; every painted text, in paint order.
    pub(crate) fn frame(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        show: &mut dyn FnMut(&mut egui::Ui),
    ) -> Vec<(String, egui::Rect)> {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(700.0, 400.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| show(ui));
            },
        );
        let mut texts = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut texts);
        }
        texts
    }

    /// Clicks the painted text that starts with `target` and returns the
    /// texts of the frame after the click.
    pub(crate) fn click(
        ctx: &egui::Context,
        target: &str,
        show: &mut dyn FnMut(&mut egui::Ui),
    ) -> Vec<(String, egui::Rect)> {
        for _ in 0..2 {
            frame(ctx, vec![], show);
        }
        let pos = frame(ctx, vec![], show)
            .into_iter()
            .find(|(text, _)| text.starts_with(target))
            .unwrap_or_else(|| panic!("{target} is not painted"))
            .1
            .center();
        let press = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        frame(ctx, vec![egui::Event::PointerMoved(pos)], show);
        frame(ctx, vec![press(true)], show);
        frame(ctx, vec![press(false)], show);
        frame(ctx, vec![], show)
    }

    /// The painted texts equal to one of `names`, top to bottom.
    pub(crate) fn column_order(texts: &[(String, egui::Rect)], names: &[&str]) -> Vec<String> {
        let mut found: Vec<_> = texts
            .iter()
            .filter(|(text, _)| names.contains(&text.as_str()))
            .collect();
        found.sort_by(|a, b| a.1.top().total_cmp(&b.1.top()));
        found.into_iter().map(|(text, _)| text.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing;
    use super::*;

    fn click(ctx: &egui::Context, table: &str, text: &str) -> String {
        let mut show = |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                header(ui, table, 0, "Name");
                header(ui, table, 1, "Size");
            });
        };
        testing::click(ctx, text, &mut show)
            .into_iter()
            .map(|(text, _)| text)
            .collect::<Vec<_>>()
            .join("|")
    }

    #[test]
    fn header_clicks_sort_ascending_then_descending_and_show_the_arrow() {
        let ctx = egui::Context::default();
        let table = "table-sort-test";
        let values = [3, 1, 2];
        let by = |ctx: &egui::Context| {
            order(ctx, table, values.len(), |_, a, b| {
                values[a].cmp(&values[b])
            })
        };
        assert_eq!(by(&ctx), vec![0, 1, 2], "recorded order until a click");
        let drawn = click(&ctx, table, "Name");
        assert!(drawn.contains("Name ▲"), "{drawn}");
        assert_eq!(by(&ctx), vec![1, 2, 0]);
        let drawn = click(&ctx, table, "Name");
        assert!(drawn.contains("Name ▼"), "{drawn}");
        assert_eq!(by(&ctx), vec![0, 2, 1]);
        // Another column starts ascending again; the first loses its arrow.
        let drawn = click(&ctx, table, "Size");
        assert!(
            drawn.contains("Size ▲") && !drawn.contains("Name ▲"),
            "{drawn}"
        );
    }

    #[test]
    fn equal_rows_keep_their_recorded_order() {
        let ctx = egui::Context::default();
        let table = "table-sort-ties";
        click(&ctx, table, "Name");
        let rows = order(&ctx, table, 4, |_, _, _| Ordering::Equal);
        assert_eq!(rows, vec![0, 1, 2, 3]);
    }
}
