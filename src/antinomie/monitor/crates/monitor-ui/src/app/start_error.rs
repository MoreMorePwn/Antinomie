// SPDX-License-Identifier: GPL-3.0-only
//! The screen shown instead of the app when the backend did not start: no
//! command can reach a backend that is not there, so nothing else is drawn.

use super::*;

/// What to do about a start failure, by what the error says.
pub(super) fn advice(error: &str) -> &'static str {
    if error.contains("migration") {
        "Antinomie found data from an older version and could not move it into the new data folder. \
         Close every other Antinomie window, then press Retry. If this stays, move or delete the new data folder \
         (the path is under Settings once the app starts, by default ~/antinomie) if it holds nothing you need, then Retry."
    } else {
        "Fix the cause named above (a full disk, a folder you cannot write to, another Antinomie still running), then press Retry."
    }
}

/// Start the backend; the one place both startup and Retry go through.
pub(super) fn start_backend(
    options: &BackendOptions,
    ctx: &egui::Context,
) -> Result<Backend, String> {
    let ctx = ctx.clone();
    Backend::new_with_wake(
        options.clone(),
        std::sync::Arc::new(move || ctx.request_repaint_of(egui::ViewportId::ROOT)),
    )
}

impl MonitorApp {
    /// Draw the blocking error screen when the backend failed to start.
    /// Returns whether it was drawn (the normal UI is then skipped).
    pub(super) fn start_error_screen(&mut self, ctx: &egui::Context) -> bool {
        let Some(error) = self.start_error.clone() else {
            return false;
        };
        let mut retry = false;
        let mut quit = false;
        crate::title_bar::show(ctx, "Antinomie");
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(720.0);
                ui.add_space(48.0);
                ui.label(
                    RichText::new("Antinomie could not start")
                        .heading()
                        .color(theme::heading()),
                );
                ui.add_space(12.0);
                ui.label("The part of Antinomie that runs the VMs did not start, so nothing in the window would work. The reason:");
                ui.add_space(6.0);
                ui.add(egui::Label::new(RichText::new(&error).monospace().color(theme::error())).wrap());
                ui.add_space(12.0);
                ui.label(RichText::new("What to do").strong());
                ui.add(egui::Label::new(advice(&error)).wrap());
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    retry = ui.button("Retry").clicked();
                    quit = ui.button("Quit").clicked();
                });
            });
        });
        if retry {
            match start_backend(&self.options, ctx) {
                Ok(backend) => {
                    self.backend = Some(backend);
                    self.start_error = None;
                    self.status.clear();
                }
                Err(error) => self.start_error = Some(error),
            }
        }
        if quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        true
    }
}
