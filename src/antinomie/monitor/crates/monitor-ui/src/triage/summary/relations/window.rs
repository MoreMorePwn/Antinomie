// SPDX-License-Identifier: GPL-3.0-only
//! The Relationships graph in a window of its own: an immediate egui viewport
//! like the activity graph's, resizable, showing the box's graph with the same
//! controls and open groups. It lives while the Triage view does.
use super::super::super::TriageView;
use super::ui;
use crate::theme;
use eframe::egui;

const SIZE: [f32; 2] = [1100.0, 720.0];
const MIN_SIZE: [f32; 2] = [560.0, 420.0];

fn window_id(run: &str) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("summary-relations-window", run))
}

impl TriageView {
    /// Show the window if it is open. Called every frame from the app.
    pub(in crate::triage) fn show_relations_window(&mut self, ctx: &egui::Context) {
        if !self.summary_state.window_open {
            return;
        }
        let run = self.scan_request.identity.as_ref().map(|id| id.2.clone());
        // Opened from the box: it belongs to the run on screen.
        if self.summary_state.window_run.is_none() {
            self.summary_state.window_run.clone_from(&run);
        }
        if run.is_none() || run != self.summary_state.window_run {
            self.summary_state.window_open = false;
            self.summary_state.window_run = None;
            return;
        }
        let run = run.unwrap_or_default();
        let title = format!("Relationships \u{b7} run {}", &run[..run.len().min(8)]);
        let builder = crate::title_bar::builder(egui::ViewportBuilder::default())
            .with_title(title.clone())
            .with_inner_size(SIZE)
            .with_min_inner_size(MIN_SIZE);
        let mut state = std::mem::take(&mut self.summary_state);
        let mut acts = Vec::new();
        let mut closed = false;
        ctx.show_viewport_immediate(window_id(&run), builder, |viewport_ui, class| {
            let ctx = &viewport_ui.ctx().clone();
            closed = ctx.input(|input| input.viewport().close_requested());
            if closed {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            if class == egui::ViewportClass::EmbeddedWindow {
                // Without separate windows the graph floats inside the main one.
                let mut keep = true;
                crate::widgets::window("Relationships")
                    .id(egui::Id::new(("summary-relations-fallback", &run)))
                    .open(&mut keep)
                    .default_size(SIZE)
                    .show(ctx, |ui| ui::show_window(ui, &mut state, &mut acts));
                closed = !keep;
                return;
            }
            crate::title_bar::show(viewport_ui, &title);
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(theme::bg()).inner_margin(8))
                .show(viewport_ui, |ui| ui::show_window(ui, &mut state, &mut acts));
            crate::title_bar::resize(ctx);
        });
        if closed {
            state.window_open = false;
            state.window_run = None;
        }
        self.summary_state = state;
        for act in acts {
            let mut destination = None;
            self.apply_act(ctx, act, &mut destination);
            if let Some(destination) = destination {
                self.go_to(ctx, destination);
            }
        }
    }
}
