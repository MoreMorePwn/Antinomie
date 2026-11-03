// SPDX-License-Identifier: GPL-3.0-only
//! The dock tab viewer: tab titles, close, drag buttons and context menu (moved out of `workspace`).
use super::*;

pub(super) struct Viewer<'a> {
    pub(super) app: &'a mut MonitorApp,
    pub(super) layout: &'a mut WorkspaceLayout,
    pub(super) surface: SurfaceIndex,
    /// Tabs shown with short names because their bar is too narrow.
    pub(super) tight: Vec<Panel>,
    /// The work area's tabs in bar order (see `WorkspaceLayout::work_tabs`).
    pub(super) work_tabs: Vec<Panel>,
}

impl Viewer<'_> {
    /// A tab's title; `tight` swaps in the short name and less padding.
    pub(super) fn title_for(&mut self, tab: &Panel, tight: bool) -> egui::WidgetText {
        if *tab == Panel::Activity {
            self.app.activity_title()
        } else if *tab == Panel::Jobs {
            self.app.jobs_title()
        } else if tight {
            workspace_tabs::tight_title(&self.app.panel_title(tab)).into()
        } else {
            theme::tab_title(&self.app.panel_title(tab)).into()
        }
    }
}

impl TabViewer for Viewer<'_> {
    type Tab = Panel;
    fn title(&mut self, tab: &mut Panel) -> egui::WidgetText {
        let tight = self.tight.contains(tab);
        self.title_for(tab, tight)
    }
    fn id(&mut self, tab: &mut Panel) -> egui::Id {
        egui::Id::new(format!("{tab:?}"))
    }
    fn ui(&mut self, ui: &mut egui::Ui, tab: &mut Panel) {
        self.app.show_panel(ui, tab);
    }
    fn scroll_bars(&self, _: &Panel) -> [bool; 2] {
        [false, false]
    }
    fn allowed_in_windows(&self, _: &mut Panel) -> bool {
        false
    }
    fn is_closeable(&self, tab: &Panel) -> bool {
        matches!(
            tab,
            Panel::Terminal(_) | Panel::AnalysisSection { .. } | Panel::Library(_)
        )
    }
    fn on_close(&mut self, tab: &mut Panel) -> egui_dock::tab_viewer::OnCloseResponse {
        if let Panel::Terminal(id) = tab {
            self.app.close_terminal_view(id);
        }
        egui_dock::tab_viewer::OnCloseResponse::Close
    }
    fn on_tab_button(&mut self, tab: &mut Panel, response: &egui::Response) {
        let origin = response
            .ctx
            .input(|input| input.viewport().inner_rect.map(|rect| rect.min))
            .unwrap_or_default();
        let visible = response
            .interact_rect
            .intersect(response.ctx.content_rect());
        if visible.is_positive() {
            self.layout.tab_targets.push((
                tab.clone(),
                self.surface,
                visible.translate(origin.to_vec2()),
            ));
        }
        if response.drag_started_by(egui::PointerButton::Primary) {
            self.layout.drag = Some((tab.clone(), self.surface));
        }
        if response.clicked() {
            self.app.details_follow.chose(tab);
        }
        if self.layout.drag.is_none() {
            response
                .clone()
                .on_hover_cursor(egui::CursorIcon::Grab)
                .on_hover_text(format!(
                    "{}{}\nDrag to reorder or dock at a pane edge. Right-click to detach.",
                    self.app.panel_title(tab),
                    self.work_tabs
                        .iter()
                        .take(9)
                        .position(|candidate| candidate == tab)
                        .and_then(crate::app::tab_shortcut)
                        .map(|shortcut| format!(" ({})", response.ctx.format_shortcut(&shortcut)))
                        .unwrap_or_default()
                ));
        }
    }
    fn context_menu(&mut self, ui: &mut egui::Ui, tab: &mut Panel, _: egui_dock::NodePath) {
        if !self.surface.is_main()
            && ui
                .button("Dock")
                .on_hover_text("Move this tab into the main window")
                .clicked()
        {
            self.layout.dock_back = Some(tab.clone());
            ui.close();
        }
        if ui.button("Detach").clicked() {
            self.layout.detach = Some(tab.clone());
            ui.close();
        }
    }
}
