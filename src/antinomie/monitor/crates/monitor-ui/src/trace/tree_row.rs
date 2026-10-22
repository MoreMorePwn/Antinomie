// SPDX-License-Identifier: GPL-3.0-only
//! The decoded call's tree rows: branches, caret, name, value and note.
use crate::{
    theme,
    tree_lines::{self, Prefix},
};
use eframe::egui::{self, Color32, Rect};

/// One line of the decoded tree.
pub(super) struct Row<'a> {
    pub(super) id: egui::Id,
    /// The branches in front of the name; a root has none.
    pub(super) branch: &'a Prefix,
    /// Rows with children draw a caret: `Some(open by default)`.
    pub(super) expand: Option<bool>,
    pub(super) name: &'a str,
    pub(super) name_color: Color32,
    /// Monospace, in its syntax color.
    pub(super) value: Option<(&'a str, Color32)>,
    /// After the value: a decoded form, a preview or a remark.
    pub(super) note: Option<(&'a str, Color32)>,
    /// Last, a small pill: where data that is not the Entry's own came from
    /// ("at exit", "kernel copy"); the row's hover text explains it.
    pub(super) tag: Option<&'a str>,
    pub(super) selected: bool,
}

/// Draw a tree row: caret, name, then value and note aligned on a column
/// shared by the row's siblings. A click selects; the caret or a double
/// click opens and closes. Returns the response and whether the row is open.
pub(super) fn tree_row(ui: &mut egui::Ui, row: Row<'_>) -> (egui::Response, bool) {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = theme::mono(body.size - 1.0);
    let height = theme::row_height(body.size);
    let caret = body.size;
    let char_width = tree_lines::char_width(ui, &mono);
    let name_x = 2.0 + row.branch.width(char_width) + caret;
    let painter = ui.painter();
    let name = painter.layout_no_wrap(row.name.to_owned(), body.clone(), row.name_color);
    let value = row
        .value
        .map(|(text, color)| painter.layout_no_wrap(text.to_owned(), mono.clone(), color));
    let note = row
        .note
        .map(|(text, color)| painter.layout_no_wrap(text.to_owned(), body.clone(), color));
    let tag_font = egui::FontId::proportional(body.size * 0.8);
    let tag_tone = crate::widgets::Tone::Info;
    let tag = row
        .tag
        .map(|text| painter.layout_no_wrap(text.to_owned(), tag_font, tag_tone.fg()));
    let gap = body.size * 0.8;
    let value_x = (name_x + name.size().x + gap).max(name_x + body.size * 6.5);
    let note_x = value_x + value.as_ref().map_or(0.0, |value| value.size().x + gap);
    let tag_x = note_x + note.as_ref().map_or(0.0, |note| note.size().x + gap);
    let pad = body.size * 0.4;
    let end = tag.as_ref().map_or(
        note_x + note.as_ref().map_or(0.0, |note| note.size().x),
        |tag| tag_x + tag.size().x + 2.0 * pad,
    ) + 4.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(end), height),
        egui::Sense::click(),
    );
    let mut open = false;
    if let Some(default) = row.expand {
        open = ui.data_mut(|data| *data.get_temp_mut_or(row.id, default));
        let caret_rect = egui::Rect::from_min_size(
            egui::pos2(rect.left() + name_x - caret, rect.top()),
            egui::vec2(caret, height),
        );
        let on_caret = response.clicked()
            && response
                .interact_pointer_pos()
                .is_some_and(|pos| caret_rect.contains(pos));
        if on_caret || response.double_clicked() {
            open = !open;
            ui.data_mut(|data| data.insert_temp(row.id, open));
        }
    }
    if ui.is_rect_visible(rect) {
        let palette = theme::palette();
        let painter = ui.painter();
        if row.selected {
            painter.rect_filled(rect, 2.0, palette.selection);
        } else if response.hovered() {
            painter.rect_filled(rect, 2.0, palette.hover);
        }
        let y = rect.center().y;
        let reach = ui.spacing().item_spacing.y * 0.5;
        let lines = Rect::from_min_max(
            egui::pos2(rect.left() + 2.0, rect.top() - reach),
            egui::pos2(rect.right(), rect.bottom() + reach),
        );
        row.branch.paint(painter, lines, char_width);
        if row.expand.is_some() {
            painter.text(
                egui::pos2(rect.left() + name_x - caret * 0.5, y),
                egui::Align2::CENTER_CENTER,
                if open {
                    egui_phosphor::regular::CARET_DOWN
                } else {
                    egui_phosphor::regular::CARET_RIGHT
                },
                body.clone(),
                theme::muted(),
            );
        }
        let place = |x: f32, galley: &std::sync::Arc<egui::Galley>| {
            egui::pos2(rect.left() + x, y - galley.size().y / 2.0)
        };
        painter.galley(place(name_x, &name), name.clone(), row.name_color);
        if let Some(value) = value {
            painter.galley(place(value_x, &value), value.clone(), theme::text());
        }
        if let Some(note) = note {
            painter.galley(place(note_x, &note), note.clone(), theme::muted());
        }
        if let Some(tag) = tag {
            let at = place(tag_x + pad, &tag);
            let pill = Rect::from_min_size(at, tag.size()).expand2(egui::vec2(pad, 1.0));
            painter.rect_filled(pill, pill.height() / 2.0, tag_tone.bg());
            painter.galley(at, tag.clone(), tag_tone.fg());
        }
    }
    (response, open)
}

/// A top-level section of the tree (Arguments, Phases); true when open.
pub(super) fn section_row(
    ui: &mut egui::Ui,
    id: egui::Id,
    title: &str,
    default_open: bool,
) -> bool {
    let (response, open) = tree_row(
        ui,
        Row {
            id,
            branch: &Prefix::default(),
            expand: Some(default_open),
            name: title,
            name_color: theme::heading(),
            value: None,
            note: None,
            tag: None,
            selected: false,
        },
    );
    // A section has nothing to select: a click anywhere opens or closes it.
    if response.clicked() && !response.double_clicked() {
        let caret = egui::TextStyle::Body.resolve(ui.style()).size + 2.0;
        let on_caret = response
            .interact_pointer_pos()
            .is_some_and(|pos| pos.x < response.rect.left() + caret);
        if !on_caret {
            let open = !open;
            ui.data_mut(|data| data.insert_temp(id, open));
            return open;
        }
    }
    open
}

/// A remark in the tree, such as "Arguments unavailable".
pub(super) fn note_row(ui: &mut egui::Ui, branch: &Prefix, text: &str, color: Color32) {
    tree_row(
        ui,
        Row {
            id: ui.id().with(("note", branch.levels(), text)),
            branch,
            expand: None,
            name: text,
            name_color: color,
            value: None,
            note: None,
            tag: None,
            selected: false,
        },
    );
}
