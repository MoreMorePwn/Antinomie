// SPDX-License-Identifier: GPL-3.0-only
//! Small drawing helpers the sample window's tabs share.
use super::*;

/// A Summary section: its label (with a count when it has one), then `body`.
pub(super) fn section(
    ui: &mut egui::Ui,
    title: &str,
    count: Option<usize>,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(title)
                .strong()
                .color(theme::palette().heading),
        );
        if let Some(count) = count {
            ui.label(RichText::new(count.to_string()).color(theme::muted()));
        }
    });
    ui.add_space(2.0);
    body(ui);
}

/// One muted line: what a section has instead of rows.
pub(super) fn muted_line(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(theme::muted()));
}

/// The accent link under a table that opens the full view.
pub(super) fn more(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_space(2.0);
    widgets::link(ui, text)
}

/// A label and a value in a key/value grid row, the value copyable.
pub(super) fn copyable(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).color(theme::muted()));
    if value.is_empty() {
        ui.label(theme::hint_text("Not computed"));
        ui.end_row();
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::Label::new(RichText::new(value).monospace().small())
                .wrap()
                .selectable(true),
        );
        if !value.is_empty()
            && ui
                .small_button(egui_phosphor::regular::COPY)
                .on_hover_text(format!("Copy {label}"))
                .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
    });
    ui.end_row();
}

/// What a page that scrolls keeps free at its right edge for the scroll bar.
pub(super) const SCROLL_GUTTER: f32 = 14.0;

/// The space between the rows of a key/value grid in a panel.
pub(super) const ROW_GAP: f32 = 8.0;

/// The panel a Summary block sits in: one fill, one border, one inner margin,
/// so no table or grid in it reaches the border.
pub(super) fn panel_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(theme::palette().panel)
        .stroke(egui::Stroke::new(1.0_f32, theme::palette().line_soft))
        .corner_radius(6)
        .inner_margin(14)
}

/// The width a grid's value column may take in `ui`: what is left after the
/// widest of `labels`, the gap between the columns and `extra` (a button
/// beside the value). Values wrap at it instead of widening the grid.
pub(super) fn value_width(ui: &egui::Ui, labels: &[&str], extra: f32) -> f32 {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let widest = labels
        .iter()
        .map(|label| {
            ui.painter()
                .layout_no_wrap((*label).to_owned(), body.clone(), theme::text())
                .size()
                .x
        })
        .fold(0.0_f32, f32::max);
    (ui.available_width() - widest - 12.0 - extra).max(80.0)
}

/// `copyable` for a grid whose value column is `max_width` wide at most: the
/// value wraps inside it and the copy button stays beside it.
pub(super) fn copyable_in(ui: &mut egui::Ui, label: &str, value: &str, max_width: f32) {
    ui.label(RichText::new(label).color(theme::muted()));
    if value.is_empty() {
        ui.label(theme::hint_text("Not computed"));
        ui.end_row();
        return;
    }
    ui.horizontal(|ui| {
        ui.scope(|ui| {
            ui.set_max_width(max_width);
            ui.add(
                egui::Label::new(RichText::new(value).monospace().small())
                    .wrap()
                    .selectable(true),
            );
        });
        if ui
            .small_button(egui_phosphor::regular::COPY)
            .on_hover_text(format!("Copy {label}"))
            .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
    });
    ui.end_row();
}

/// A key/value grid row whose value wraps within `max_width`.
pub(super) fn row_in(
    ui: &mut egui::Ui,
    label: &str,
    value: impl Into<egui::WidgetText>,
    max_width: f32,
) {
    ui.label(RichText::new(label).color(theme::muted()));
    ui.scope(|ui| {
        ui.set_max_width(max_width);
        ui.add(egui::Label::new(value).wrap().selectable(true));
    });
    ui.end_row();
}

/// The spot in a right-click menu where the notes feature adds its
/// "Add note…" item (artifact rows, lineage nodes). Nothing is drawn yet.
pub(super) fn add_note_menu_item(_ui: &mut egui::Ui) {}

/// The accent link beside a label on one line (no gap above it).
pub(super) fn more_inline(ui: &mut egui::Ui, text: &str) -> egui::Response {
    widgets::link(ui, text)
}

/// A key/value grid row with a plain value.
pub(super) fn row(ui: &mut egui::Ui, label: &str, value: impl Into<egui::WidgetText>) {
    ui.label(RichText::new(label).color(theme::muted()));
    ui.add(egui::Label::new(value).selectable(true));
    ui.end_row();
}

/// The run as the sample window names it: "Run 3".
pub(super) fn run_name(number: usize) -> String {
    format!("Run {number}")
}

/// Latest-run style time: the host's local zone to the minute.
pub(super) fn minute(ms: Option<u64>) -> String {
    super::super::list::started(ms)
}

/// Seconds-precision local time for event rows.
pub(super) fn second(ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "Unavailable".into())
}

/// A table of fixed height inside a scrolling page: the body never scrolls
/// on its own.
pub(super) fn mini_table<'a>(ui: &'a mut egui::Ui, id: &str) -> TableBuilder<'a> {
    widgets::table::begin(ui);
    TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .vscroll(false)
}

/// A text column's width for its longest text: the text, the cell's padding
/// and a little slack, within bounds so one long name cannot take the row.
pub(super) fn fitted_width(text_width: f32, most: f32) -> f32 {
    (text_width + 20.0).clamp(80.0, most.max(80.0))
}

/// The width a column needs for the longest of `texts` (and its header) drawn
/// in `font`.
pub(super) fn fitted(
    ui: &egui::Ui,
    font: &egui::FontId,
    texts: impl IntoIterator<Item = String>,
) -> f32 {
    fitted_up_to(ui, font, texts, 260.0)
}

/// `fitted` with the widest the column may get.
pub(super) fn fitted_up_to(
    ui: &egui::Ui,
    font: &egui::FontId,
    texts: impl IntoIterator<Item = String>,
    most: f32,
) -> f32 {
    let widest = texts
        .into_iter()
        .map(|text| {
            ui.painter()
                .layout_no_wrap(text, font.clone(), theme::text())
                .size()
                .x
        })
        .fold(0.0_f32, f32::max);
    fitted_width(widest, most)
}

#[cfg(test)]
mod fit_tests {
    use super::fitted_width;

    #[test]
    fn a_text_column_fits_its_longest_name_within_bounds() {
        assert_eq!(fitted_width(100.0, 260.0), 120.0);
        assert_eq!(fitted_width(5.0, 260.0), 80.0);
        assert_eq!(fitted_width(900.0, 260.0), 260.0);
        assert_eq!(fitted_width(300.0, 400.0), 320.0);
    }
}
