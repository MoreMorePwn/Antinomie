// SPDX-License-Identifier: GPL-3.0-only
//! The graph in its own OS window: one per run, resizable, with the same
//! filter bar, chips, selection and Details as the Suspicious activity table.
//! It is an immediate egui viewport, shown from the same place the finding
//! Details windows are, so it lives while the Triage view does.
use super::view::State;
use super::*;
use std::collections::BTreeMap;

/// The size a first window opens at, in points.
pub(in crate::triage) const DEFAULT_SIZE: [f32; 2] = [1180.0, 760.0];
/// The smallest the window can be made.
const MIN_SIZE: [f32; 2] = [640.0, 520.0];
/// Details beside the graph need at least this much width to leave the graph room.
const DETAILS_FROM: f32 = 900.0;

pub(in crate::triage) struct Window {
    pub open: bool,
    /// Details beside the graph (when the window is wide enough).
    pub details: bool,
    /// Width of the Details beside the graph, which a splitter changes.
    pub details_width: f32,
    /// Its own window, scroll and fold state; the selection is the table's.
    pub state: State,
    /// The run the window shows; it closes when another run is selected.
    run: Option<String>,
    /// What each run's window last measured, for this session.
    sizes: BTreeMap<String, [f32; 2]>,
    /// The size a window opens at when its run has none yet.
    pub default_size: [f32; 2],
    /// A size to hand to the app's settings, once.
    changed: Option<[f32; 2]>,
    /// The size this window was built with. Egui compares builders, so the
    /// measured size is kept apart and never fed back into it.
    opened_at: [f32; 2],
    /// Frames the viewport was drawn, for tests.
    #[cfg(test)]
    pub drawn: u64,
}

impl Default for Window {
    fn default() -> Self {
        Self {
            open: false,
            details: true,
            details_width: 380.0,
            state: State::default(),
            run: None,
            sizes: BTreeMap::new(),
            default_size: DEFAULT_SIZE,
            changed: None,
            opened_at: DEFAULT_SIZE,
            #[cfg(test)]
            drawn: 0,
        }
    }
}

impl Window {
    /// Open the window for `run`; a second request while it is open does nothing
    /// but ask for the same window to come forward.
    pub(in crate::triage) fn open_for(&mut self, run: &str) -> bool {
        if self.open && self.run.as_deref() == Some(run) {
            return false;
        }
        self.opened_at = self.sizes.get(run).copied().unwrap_or(self.default_size);
        self.run = Some(run.to_owned());
        self.open = true;
        true
    }

    #[cfg(test)]
    pub(in crate::triage) fn opened_at(&self) -> [f32; 2] {
        self.opened_at
    }

    pub(in crate::triage) fn close(&mut self) {
        self.open = false;
        self.run = None;
    }

    fn remember(&mut self, size: [f32; 2]) {
        let Some(run) = self.run.clone() else {
            return;
        };
        let size = [size[0].round(), size[1].round()];
        if self.sizes.insert(run, size) != Some(size) {
            self.default_size = size;
            self.changed = Some(size);
        }
    }
}

impl TriageView {
    /// Open (or bring forward) the graph window of the run on screen.
    pub(in crate::triage) fn open_graph_window(&mut self, ctx: &egui::Context) {
        let Some(run) = self.scan_request.identity.as_ref().map(|id| id.2.clone()) else {
            return;
        };
        if !self.graph_window.open_for(&run) {
            ctx.send_viewport_cmd_to(window_id(&run), egui::ViewportCommand::Focus);
        }
        ctx.request_repaint();
    }

    /// The size a window opens at, from the app's settings.
    pub(crate) fn set_graph_window_size(&mut self, size: [f32; 2]) {
        if size[0] >= MIN_SIZE[0] && size[1] >= MIN_SIZE[1] {
            self.graph_window.default_size = size;
        }
    }

    /// A size to save in the settings, when the window was resized.
    pub(crate) fn take_graph_window_size(&mut self) -> Option<[f32; 2]> {
        self.graph_window.changed.take()
    }

    /// Show the graph window if it is open. Called every frame from the app.
    pub(in crate::triage) fn show_graph_window(&mut self, ctx: &egui::Context) {
        if !self.graph_window.open {
            return;
        }
        let Some(run) = self.scan_request.identity.as_ref().map(|id| id.2.clone()) else {
            self.graph_window.close();
            return;
        };
        if self.graph_window.run.as_deref() != Some(run.as_str()) {
            self.graph_window.close();
            return;
        }
        let title = format!("Activity graph · run {}", &run[..run.len().min(8)]);
        let size = self.graph_window.opened_at;
        let builder = crate::title_bar::builder(egui::ViewportBuilder::default())
            .with_title(title.clone())
            .with_inner_size(size)
            .with_min_inner_size(MIN_SIZE);
        let mut closed = false;
        ctx.show_viewport_immediate(window_id(&run), builder, |ctx, class| {
            closed = ctx.input(|input| input.viewport().close_requested());
            if closed {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
            // Read back below: the closure cannot return while it borrows `self`.
            #[cfg(test)]
            {
                self.graph_window.drawn += 1;
            }
            if class == egui::ViewportClass::Embedded {
                // Without separate windows the graph floats inside the main one.
                let mut keep = true;
                crate::widgets::window("Activity graph")
                    .id(egui::Id::new(("graph-window-fallback", &run)))
                    .open(&mut keep)
                    .default_size(size)
                    .show(ctx, |ui| self.graph_window_body(ui));
                closed = !keep;
                return;
            }
            if let Some(inner) = ctx.input(|input| input.viewport().inner_rect) {
                if inner.width() >= MIN_SIZE[0] && inner.height() >= MIN_SIZE[1] {
                    self.graph_window.remember([inner.width(), inner.height()]);
                }
            }
            crate::title_bar::show(ctx, &title);
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(theme::bg()).inner_margin(8))
                .show(ctx, |ui| self.graph_window_body(ui));
            crate::title_bar::resize(ctx);
        });
        if closed {
            self.graph_window.close();
        }
    }

    /// The filter bar, then the graph, with Details to its right.
    fn graph_window_body(&mut self, ui: &mut egui::Ui) {
        let (shown, unplaced) = self.scan.as_ref().map_or((0, 0), |scan| {
            (scan.graph.index.records.len(), scan.graph.index.unplaced)
        });
        self.query_bar(
            ui,
            0,
            FINDING_FIELDS,
            "finding.tier == high",
            (shown, shown as u64 + unplaced),
            Bar::Graph,
        );
        let wide = ui.available_width() >= DETAILS_FROM;
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.graph_window.details, "Details beside the graph")
                .on_hover_text("The selected finding, as in the Details panel");
            super::legend::button(ui);
            if unplaced > 0 {
                ui.colored_label(
                    theme::warn(),
                    format!("{unplaced} findings without a time are not on the graph."),
                );
            }
        });
        let details = self.graph_window.details && wide;
        let room = ui.available_size();
        let width = self.graph_window.details_width.clamp(260.0, room.x * 0.6);
        let gap = 10.0;
        let graph_width = if details {
            room.x - width - gap
        } else {
            room.x
        };
        let mut state = std::mem::take(&mut self.graph_window.state);
        let mut dragged = 0.0;
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(graph_width, room.y),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    let height = ui.available_height().max(300.0);
                    self.draw_graph(ui, &mut state, details, height);
                },
            );
            if !details {
                return;
            }
            // A splitter between the graph and Details.
            let (bar, response) =
                ui.allocate_exact_size(egui::vec2(gap, room.y), egui::Sense::drag());
            let hot = response.hovered() || response.dragged();
            ui.painter().vline(
                bar.center().x,
                bar.y_range(),
                egui::Stroke::new(
                    if hot { 2.0_f32 } else { 1.0_f32 },
                    if hot { theme::blue() } else { theme::line() },
                ),
            );
            if hot {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            }
            dragged = response.drag_delta().x;
            ui.allocate_ui_with_layout(
                egui::vec2(width, room.y),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::Frame::NONE
                        .fill(theme::panel())
                        .inner_margin(8)
                        .show(ui, |ui| {
                            ui.set_min_size(ui.available_size());
                            details::show(self, ui);
                        });
                },
            );
        });
        self.graph_window.state = state;
        self.graph_window.details_width = (width - dragged).clamp(260.0, room.x * 0.6);
    }
}

pub(in crate::triage) fn window_id(run: &str) -> egui::ViewportId {
    egui::ViewportId::from_hash_of(("triage-graph-window", run))
}
