// SPDX-License-Identifier: GPL-3.0-only
//! Reads of the workspace layout for the rendered tests.
use super::{Panel, WorkspaceLayout};
use eframe::egui;

impl WorkspaceLayout {
    /// Where a new workspace window with no saved geometry opens (for the
    /// rendered tests): `None` until the main window has been drawn.
    #[cfg(test)]
    pub(crate) fn new_window_position(&mut self) -> Option<egui::Pos2> {
        let surface = self
            .dock
            .add_window(vec![Panel::Terminal("position-probe".into())]);
        let position = self.native_builder(surface.0, String::new()).position;
        self.dock.remove_surface(surface);
        self.native_builders.remove(&surface.0);
        position
    }

    /// The other tabs of the pane `panel` is in (for the rendered tests).
    #[cfg(test)]
    pub(crate) fn tabs_beside(&self, panel: &Panel) -> Vec<Panel> {
        let Some(at) = self.dock.find_tab(panel) else {
            return Vec::new();
        };
        self.dock
            .iter_all_tabs()
            .filter(|(path, other)| {
                path.surface == at.surface && path.node == at.node && *other != panel
            })
            .map(|(_, other)| other.clone())
            .collect()
    }
}

impl WorkspaceLayout {
    /// Put `panel` in a pane of its own, split off Run History's pane on the
    /// `split` side with the old pane's part at `fraction`, and show it (for
    /// the rendered tests and the split screenshots).
    #[cfg(test)]
    pub(crate) fn split_beside_history(
        &mut self,
        panel: &Panel,
        split: egui_dock::Split,
        fraction: f32,
    ) {
        if let Panel::Library(page) = panel {
            self.open_library(*page);
        }
        // Run History itself is split off Overview's pane.
        let anchor = if *panel == Panel::RunHistory {
            Panel::Summary
        } else {
            Panel::RunHistory
        };
        let Some(location) = self.dock.find_tab(panel) else {
            return;
        };
        let _ = self.dock.remove_tab(location);
        let Some(history) = self.dock.find_tab(&anchor) else {
            return;
        };
        self.dock[history.surface].split(
            history.node,
            split,
            fraction,
            egui_dock::Node::leaf(panel.clone()),
        );
        self.focus(panel.clone());
    }
}
