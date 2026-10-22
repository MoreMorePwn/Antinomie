// SPDX-License-Identifier: GPL-3.0-only
//! Scrolling for the Details panel: one vertical area with a stable id, kept
//! where the user left it while the same thing stays selected, and a process
//! tree height that grows with the window and can be dragged.
use eframe::egui;
use std::hash::{Hash, Hasher};

/// Smallest and default share of the panel the process tree takes.
const MIN_TREE: f32 = 260.0;
const TREE_SHARE: f32 = 0.65;
/// The splitter's limits, so a drag cannot hide the tree or push the rest off.
const MIN_DRAGGED: f32 = 100.0;
const MAX_DRAGGED: f32 = 4000.0;

/// Shows `add` in a vertical scroll area named `id`. `add` gets the height the
/// panel has, which the scrolled content no longer reports. The offset is
/// reset to the top once, on the frame `selection` differs from the last one
/// drawn; it is never set otherwise, so a repaint cannot move it.
pub(crate) fn show<R>(
    ui: &mut egui::Ui,
    id: &'static str,
    selection: impl Hash,
    add: impl FnOnce(&mut egui::Ui, f32) -> R,
) -> R {
    let viewport = ui.available_height();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    selection.hash(&mut hasher);
    let key = hasher.finish();
    let seen = ui.id().with((id, "selection"));
    let before = ui.data_mut(|data| data.get_temp::<u64>(seen));
    ui.data_mut(|data| data.insert_temp(seen, key));
    let mut area = egui::ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false]);
    // The first draw has nothing to reset: the area restores its own offset.
    if before.is_some_and(|before| before != key) {
        area = area.vertical_scroll_offset(0.0);
    }
    area.show(ui, |ui| add(ui, viewport)).inner
}

/// The height of the process tree in a panel `viewport` high: the user's drag
/// if there is one, else most of the panel (never under `MIN_TREE`).
pub(crate) fn tree_height(ui: &egui::Ui, viewport: f32) -> f32 {
    let viewport = if viewport.is_finite() { viewport } else { 0.0 };
    ui.data(|data| data.get_temp::<f32>(height_id()))
        .unwrap_or((viewport * TREE_SHARE).max(MIN_TREE))
        .clamp(MIN_DRAGGED, MAX_DRAGGED)
}

/// A handle under the tree: drag to resize, double-click to go back to the
/// default height.
pub(crate) fn tree_splitter(ui: &mut egui::Ui, height: f32) {
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 8.0),
        egui::Sense::click_and_drag(),
    );
    let response = response
        .on_hover_cursor(egui::CursorIcon::ResizeVertical)
        .on_hover_text("Drag to resize the tree; double-click to reset");
    if response.double_clicked() {
        ui.data_mut(|data| data.remove_temp::<f32>(height_id()));
    } else if response.dragged() {
        let wanted = (height + response.drag_delta().y).clamp(MIN_DRAGGED, MAX_DRAGGED);
        ui.data_mut(|data| data.insert_temp(height_id(), wanted));
    }
    let stroke = if response.hovered() || response.dragged() {
        ui.visuals().widgets.hovered.fg_stroke
    } else {
        ui.visuals().widgets.noninteractive.bg_stroke
    };
    ui.painter().hline(rect.x_range(), rect.center().y, stroke);
}

fn height_id() -> egui::Id {
    egui::Id::new("details-process-tree-height")
}
