// SPDX-License-Identifier: GPL-3.0-only
//! The table style of the mockup for `egui_extras::TableBuilder`: a header
//! row in the panel color with muted semibold labels and a rule under it,
//! zebra rows, hover and selection fills (from the theme's visuals), a 3 px
//! accent bar on the selected row, monospace and right-aligned numeric
//! columns. Table contents and logic stay with each view; only the look is
//! shared.
//!
//! ```ignore
//! table::begin(ui);
//! TableBuilder::new(ui).striped(true)/* columns */
//!     .header(table::header_height(font), |mut header| {
//!         header.col(|ui| table::head(ui, "Time"));
//!     })
//!     .body(|body| body.rows(table::row_height(font), n, |mut row| {
//!         row.set_selected(selected);
//!         row.col(|ui| {
//!             table::row_mark(ui, if selected { Mark::Selected } else { Mark::None });
//!             table::cell(ui, Cell::Mono, &time);
//!         });
//!         row.col(|ui| table::cell(ui, Cell::Number, &size));
//!     }));
//! ```
use crate::theme;
use eframe::egui::{self, vec2, Align, Layout, RichText, Stroke};

/// Height of one body row for text of `font_size` (density aware).
pub fn row_height(font_size: f32) -> f32 {
    theme::row_height(font_size)
}

/// Height of the header row.
pub fn header_height(font_size: f32) -> f32 {
    theme::row_height(font_size) + 4.0
}

/// How a cell's text is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    /// Proportional text.
    Text,
    /// Monospace: times, PIDs, addresses, hashes, results.
    Mono,
    /// Right-aligned monospace: sizes, counts, durations.
    Number,
}

/// A flag bar at the left edge of a row's first cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    None,
    /// The selected row: accent.
    Selected,
    /// A flagged row: warn.
    Flagged,
    /// A failed row: error.
    Failed,
}

/// Call before `TableBuilder::new(ui)`: the table area sits on the deepest
/// surface, so the panel-colored header and the zebra rows read as in the
/// mockup.
pub fn begin(ui: &mut egui::Ui) {
    let rect = ui.available_rect_before_wrap();
    ui.painter().rect_filled(rect, 0.0, theme::bg());
}

/// A header cell: muted semibold label on the panel color, rule below.
pub fn head(ui: &mut egui::Ui, text: &str) {
    head_cell(ui, |ui| {
        ui.add(egui::Label::new(head_text(text)).truncate());
    });
}

/// `Align::Max` for a numeric column, `Align::Min` for text.
pub fn numeric_align(numeric: bool) -> Align {
    if numeric {
        Align::Max
    } else {
        Align::Min
    }
}

/// Run `add` with its widgets at the left (`Align::Min`) or right
/// (`Align::Max`) edge of the cell, centred in its height: for headers.
pub fn aligned(ui: &mut egui::Ui, align: Align, add: impl FnOnce(&mut egui::Ui)) {
    if align == Align::Max {
        ui.with_layout(Layout::right_to_left(Align::Center), add);
    } else {
        add(ui);
    }
}

/// [`aligned`] for body cells of a table whose cells are centred in the row
/// (`cell_layout(left_to_right(Center))`): a right-aligned cell is centred in
/// the row too, so numbers and text in one row share a middle line however
/// their fonts differ.
pub fn aligned_cell(ui: &mut egui::Ui, align: Align, add: impl FnOnce(&mut egui::Ui)) {
    if align == Align::Max {
        ui.with_layout(Layout::right_to_left(Align::Center), add);
    } else {
        add(ui);
    }
}

/// A header cell with its label at the left or right edge (numeric columns
/// align right, like their cells).
pub fn head_aligned(ui: &mut egui::Ui, text: &str, align: Align) {
    head_bg(ui);
    aligned(ui, align, |ui| {
        ui.add(egui::Label::new(head_text(text)).truncate());
    });
}

/// The header label style, for headers that draw their own widget (a sort
/// button): muted, strong.
pub fn head_text(text: impl Into<String>) -> RichText {
    RichText::new(text).strong().color(theme::muted())
}

/// A header cell around custom content: paints the header fill and rule,
/// then runs `content`.
pub fn head_cell<R>(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    head_bg(ui);
    content(ui)
}

/// Paint only the header fill and rule of the current cell; call first in a
/// header cell that draws its own widget (a sort button).
pub fn head_bg(ui: &mut egui::Ui) {
    let spacing = ui.spacing().item_spacing;
    let rect = ui
        .max_rect()
        .expand2(vec2(spacing.x / 2.0, spacing.y / 2.0));
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, theme::panel());
    painter.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0_f32, theme::line()),
    );
}

/// Text in a body cell, truncated to the column. Colors stay the theme's
/// text color; pass value colors through `RichText` yourself when needed.
pub fn cell(ui: &mut egui::Ui, kind: Cell, text: &str) -> egui::Response {
    cell_rich(ui, kind, RichText::new(text))
}

/// `cell` for text that is already styled (a value color, strikethrough).
pub fn cell_rich(ui: &mut egui::Ui, kind: Cell, text: RichText) -> egui::Response {
    match kind {
        Cell::Text => ui.add(egui::Label::new(text).truncate()),
        Cell::Mono => ui.add(egui::Label::new(text.monospace()).truncate()),
        Cell::Number => {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add(egui::Label::new(text.monospace()).truncate())
            })
            .inner
        }
    }
}

/// `cell` for a table whose rows are clickable: the text is not selectable,
/// so a click on it reaches the row.
pub fn cell_click(ui: &mut egui::Ui, kind: Cell, text: &str) -> egui::Response {
    let text = RichText::new(text);
    match kind {
        Cell::Text => ui.add(egui::Label::new(text).selectable(false).truncate()),
        Cell::Mono => ui.add(
            egui::Label::new(text.monospace())
                .selectable(false)
                .truncate(),
        ),
        Cell::Number => {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add(
                    egui::Label::new(text.monospace())
                        .selectable(false)
                        .truncate(),
                )
            })
            .inner
        }
    }
}

/// The 3 px bar at a row's left edge; call in the row's first cell.
pub fn row_mark(ui: &mut egui::Ui, mark: Mark) {
    let color = match mark {
        Mark::None => return,
        Mark::Selected => theme::palette().accent,
        Mark::Flagged => theme::palette().warn,
        Mark::Failed => theme::palette().error,
    };
    let spacing = ui.spacing().item_spacing;
    let rect = ui
        .max_rect()
        .expand2(vec2(spacing.x / 2.0, spacing.y / 2.0));
    let bar = egui::Rect::from_min_size(rect.min, vec2(3.0, rect.height()));
    ui.painter().rect_filled(bar, 0.0, color);
}
