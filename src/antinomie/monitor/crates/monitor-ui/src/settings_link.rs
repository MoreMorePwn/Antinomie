// SPDX-License-Identifier: GPL-3.0-only
//! A button in a warning that opens the Tools > Settings page where the limit
//! the warning names is changed. The window code only asks; the app opens the
//! page at the start of the next frame.
use eframe::egui;

const REQUEST: &str = "open-settings-page";

/// A small button "Open <page> settings"; returns whether it was pressed, and
/// has already asked the app to open the page then.
pub(crate) fn button(ui: &mut egui::Ui, page: &'static str) -> bool {
    let pressed = ui
        .small_button(format!("Open {page} settings"))
        .on_hover_text(format!("Tools > Settings > {page}"))
        .clicked();
    if pressed {
        request(ui.ctx(), page);
    }
    pressed
}

/// Asks the app to show the settings page called `page` (its list label).
pub(crate) fn request(ctx: &egui::Context, page: &'static str) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new(REQUEST), page));
    ctx.request_repaint();
}

/// The page asked for since the last call, if any.
pub(crate) fn take(ctx: &egui::Context) -> Option<&'static str> {
    ctx.data_mut(|data| data.remove_temp::<&'static str>(egui::Id::new(REQUEST)))
}
