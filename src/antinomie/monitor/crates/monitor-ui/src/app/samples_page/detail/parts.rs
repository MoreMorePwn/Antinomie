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
        ui.label(theme::section_title(ui, title));
        if let Some(count) = count {
            ui.label(RichText::new(count.to_string()).color(theme::muted()));
        }
    });
    scroll_if_asked(ui, title, heading.response.rect);
    ui.add_space(2.0);
    body(ui);
}

/// Scroll to `rect` when a note's chip, or the screenshot fixture, asked for
/// the section titled `title`.
pub(super) fn scroll_if_asked(ui: &mut egui::Ui, title: &str, rect: egui::Rect) {
    let wanted = egui::Id::new("sample_scroll_to_section");
    if ui.ctx().data(|d| d.get_temp::<String>(wanted)).as_deref() == Some(title) {
        ui.ctx().data_mut(|d| d.remove::<String>(wanted));
        ui.scroll_to_rect(rect, Some(egui::Align::TOP));
    }
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

/// A grid row for a long value with a copy button: the value is cut in the
/// middle ("7dd32a00…c1e1a3") to fit `max_width` less the button, the whole of
/// it on hover, and the button copies the whole of it. An empty value reads
/// `empty` and has no button.
pub(super) fn copy_row_in(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    max_width: f32,
    empty: &str,
) {
    ui.label(RichText::new(label).color(theme::muted()));
    ui.scope(|ui| {
        ui.set_max_width(max_width);
        ui.horizontal(|ui| {
            if value.is_empty() {
                ui.label(theme::hint_text(empty));
                return;
            }
            let button = ui.spacing().interact_size.y + 4.0;
            let room = (max_width - button - ui.spacing().item_spacing.x).max(40.0);
            let mono = egui::TextStyle::Monospace.resolve(ui.style());
            let shown = crate::widgets::fit_table::middle(ui, value, &mono, room);
            let text = ui.add(
                egui::Label::new(RichText::new(&shown).font(mono))
                    .wrap_mode(egui::TextWrapMode::Extend)
                    .selectable(false),
            );
            if shown != value {
                text.on_hover_text(value);
            }
            if ui
                .small_button(egui_phosphor::regular::COPY)
                .on_hover_text(format!("Copy {label}"))
                .clicked()
            {
                ui.ctx().copy_text(value.to_owned());
            }
        });
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
    crate::time_format::local_seconds(ms / 1000)
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
pub(super) fn mini_table<'a>(ui: &'a mut egui::Ui, id: &str) -> FitBuilder<'a> {
    FitBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .vscroll(false)
}

/// A `mini_table` whose rows are clickable: its labels are not selectable, so
/// a click on the text of any cell reaches the row. Call inside `on_surface`
/// (the style change stays in that scope).
pub(super) fn click_table<'a>(ui: &'a mut egui::Ui, id: &str) -> FitBuilder<'a> {
    ui.style_mut().interaction.selectable_labels = false;
    mini_table(ui, id).sense(egui::Sense::click())
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

/// The button under a scrolling table that opens the whole list in Static
/// analysis. True when clicked.
pub(super) fn open_all(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add_space(4.0);
    ui.button(text)
        .on_hover_text("Open the whole list in Static analysis")
        .clicked()
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
