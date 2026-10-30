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
    let heading = ui.horizontal(|ui| {
        ui.label(
            RichText::new(title)
                .strong()
                .color(theme::palette().heading),
        );
        if let Some(count) = count {
            ui.label(RichText::new(count.to_string()).color(theme::muted()));
        }
    });
    // A note's chip, or the screenshot fixture, asks for a section by name.
    let wanted = egui::Id::new("sample_scroll_to_section");
    if ui.ctx().data(|d| d.get_temp::<String>(wanted)).as_deref() == Some(title) {
        ui.ctx().data_mut(|d| d.remove::<String>(wanted));
        ui.scroll_to_rect(heading.response.rect, Some(egui::Align::TOP));
    }
    ui.add_space(2.0);
    body(ui);
}

/// Scroll the Summary to the section titled `title` when it is next drawn.
pub(super) fn scroll_to_section(ctx: &egui::Context, title: &str) {
    ctx.data_mut(|data| {
        data.insert_temp(egui::Id::new("sample_scroll_to_section"), title.to_owned())
    });
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

/// Two panels side by side in `columns`, one height (the taller one's), the
/// same margin and border as [`panel_frame`].
pub(super) fn equal_boxes(
    columns: &mut [egui::Ui],
    left: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    let frame = panel_frame();
    let mut first = frame.begin(&mut columns[0]);
    first
        .content_ui
        .set_width(first.content_ui.available_width());
    left(&mut first.content_ui);
    let mut second = frame.begin(&mut columns[1]);
    second
        .content_ui
        .set_width(second.content_ui.available_width());
    right(&mut second.content_ui);
    let height = first
        .content_ui
        .min_rect()
        .height()
        .max(second.content_ui.min_rect().height());
    first.content_ui.set_min_height(height);
    second.content_ui.set_min_height(height);
    first.end(&mut columns[0]);
    second.end(&mut columns[1]);
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

/// Hash rows (label, value, copy button) of equal height and equal gaps: the
/// value wraps inside its own column, the label and the button sit centred
/// beside it, and the buttons line up at the right edge. An empty value reads
/// "Not computed" and has no button.
pub(super) fn hash_rows(ui: &mut egui::Ui, rows: &[(&str, &str)]) {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let small = egui::FontId::monospace((mono.size * 0.85).max(10.0));
    let gap = 12.0;
    let button = ui.spacing().interact_size.y + 4.0;
    let label_width = rows
        .iter()
        .map(|(label, _)| {
            ui.painter()
                .layout_no_wrap((*label).to_owned(), body.clone(), theme::text())
                .size()
                .x
        })
        .fold(0.0_f32, f32::max);
    let value_width = (ui.available_width() - label_width - button - gap * 2.0).max(80.0);
    let height = rows
        .iter()
        .map(|(_, value)| {
            ui.painter()
                .layout(
                    (*value).to_owned(),
                    small.clone(),
                    theme::text(),
                    value_width,
                )
                .size()
                .y
        })
        .fold(button, f32::max)
        + 4.0;
    for (index, (label, value)) in rows.iter().enumerate() {
        if index > 0 {
            ui.add_space(ROW_GAP);
        }
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height),
            egui::Layout::left_to_right(egui::Align::Center),
            |ui| {
                ui.spacing_mut().item_spacing.x = gap;
                ui.allocate_ui_with_layout(
                    egui::vec2(label_width, height),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_size(egui::vec2(label_width, height));
                        ui.label(RichText::new(*label).color(theme::muted()))
                    },
                );
                ui.allocate_ui_with_layout(
                    egui::vec2(value_width, height),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.set_min_size(egui::vec2(value_width, height));
                        if value.is_empty() {
                            ui.label(theme::hint_text("Not computed"));
                        } else {
                            ui.add(
                                egui::Label::new(RichText::new(*value).font(small.clone()))
                                    .wrap()
                                    .selectable(true),
                            );
                        }
                    },
                );
                if !value.is_empty()
                    && ui
                        .small_button(egui_phosphor::regular::COPY)
                        .on_hover_text(format!("Copy {label}"))
                        .clicked()
                {
                    ui.ctx().copy_text((*value).to_owned());
                }
            },
        );
    }
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

/// Run `add` (one `mini_table`) on the deepest surface: the fill covers
/// exactly what the table drew, not the rest of the scrolling page below it.
pub(super) fn on_surface<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let slot = ui.painter().add(egui::Shape::Noop);
    let drawn = ui.scope(add);
    ui.painter().set(
        slot,
        egui::epaint::RectShape::filled(drawn.response.rect, 0.0, theme::bg()),
    );
    drawn.inner
}

/// A table of fixed height inside a scrolling page: the body never scrolls
/// on its own.
pub(super) fn mini_table<'a>(ui: &'a mut egui::Ui, id: &str) -> TableBuilder<'a> {
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
