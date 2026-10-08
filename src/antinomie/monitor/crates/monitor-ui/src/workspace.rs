//! A single dock tree rendered by moving each surface into its native viewport.
use crate::{app::MonitorApp, theme};
use eframe::egui::{self, Rect};
use egui_dock::{
    DockArea, DockState, NodeIndex, Surface, SurfaceIndex, TabDestination, TabIndex, TabInsert,
    TabViewer,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Panel {
    Trace,
    StaticAnalysis,
    RunHistory,
    Details,
    Activity,
    Terminal(String),
}

impl Panel {
    pub(crate) fn title(&self) -> &str {
        match self {
            Self::Trace => "Syscall Trace",
            Self::StaticAnalysis => "Static Analysis",
            Self::RunHistory => "Run History",
            Self::Details => "Details",
            Self::Activity => "Activity",
            Self::Terminal(_) => "Terminal",
        }
    }
}

/// Bumped when the default arrangement changes, so a layout saved before the
/// change is replaced by the new default once. Version 2 also replaces layouts
/// that closing a detached window had flattened into one tab bar.
const LAYOUT_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
pub(crate) struct WorkspaceLayout {
    /// Absent (0) in layouts saved before versioning.
    #[serde(default)]
    version: u32,
    dock: DockState<Panel>,
    geometry: BTreeMap<usize, Rect>,
    #[serde(skip)]
    drag: Option<(Panel, SurfaceIndex)>,
    #[serde(skip)]
    targets: Vec<(SurfaceIndex, NodeIndex, Rect)>,
    #[serde(skip)]
    released: Option<egui::Pos2>,
    #[serde(skip)]
    detach: Option<Panel>,
}

impl Default for WorkspaceLayout {
    fn default() -> Self {
        // Run History is the first (leftmost) tab, next to the trace; the trace
        // stays the open tab so the startup view is unchanged.
        let mut dock = DockState::new(vec![Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]);
        dock.set_active_tab((SurfaceIndex::main(), NodeIndex::root(), TabIndex(1)));
        dock.main_surface_mut().split_below(
            NodeIndex::root(),
            0.63,
            vec![Panel::Details, Panel::Activity],
        );
        Self {
            version: LAYOUT_VERSION,
            dock,
            geometry: BTreeMap::new(),
            drag: None,
            targets: Vec::new(),
            released: None,
            detach: None,
        }
    }
}

impl WorkspaceLayout {
    /// The saved layout, unless it predates the current default arrangement.
    pub(crate) fn restore(saved: Option<Self>) -> Self {
        saved
            .filter(|layout| layout.version >= LAYOUT_VERSION)
            .unwrap_or_default()
    }

    pub(crate) fn validate(&mut self) {
        let mut seen = Vec::new();
        self.dock.retain_tabs(|tab| {
            if matches!(tab, Panel::Terminal(_)) || seen.contains(tab) {
                false
            } else {
                seen.push(tab.clone());
                true
            }
        });
        for panel in [
            Panel::RunHistory,
            Panel::Trace,
            Panel::StaticAnalysis,
            Panel::Details,
            Panel::Activity,
        ] {
            if self.dock.find_tab(&panel).is_none() {
                self.return_home(panel);
            }
        }
        self.geometry
            .retain(|_, rect| rect.is_finite() && rect.width() >= 200.0 && rect.height() >= 100.0);
    }

    pub(crate) fn focus(&mut self, panel: Panel) {
        if let Some((surface, node, tab)) = self.dock.find_tab(&panel) {
            self.dock.set_active_tab((surface, node, tab));
            self.dock.set_focused_node_and_surface((surface, node));
        }
    }

    pub(crate) fn show(&mut self, app: &mut MonitorApp, ctx: &egui::Context) {
        self.targets.clear();
        for (id, open) in app.terminal_views() {
            let panel = Panel::Terminal(id);
            if open && self.dock.find_tab(&panel).is_none() {
                self.dock.add_window(vec![panel]);
            } else if !open {
                if let Some(location) = self.dock.find_tab(&panel) {
                    self.dock.remove_tab(location);
                }
            }
        }
        egui::CentralPanel::default()
            .frame(theme::frame(theme::BG))
            .show(ctx, |ui| self.show_surface(app, ui, SurfaceIndex::main()));
        let surfaces: Vec<_> = (1..self.dock.surfaces_count())
            .filter(|index| self.dock.is_surface_valid(SurfaceIndex(*index)))
            .collect();
        for index in surfaces {
            let surface = SurfaceIndex(index);
            let title = self.dock[surface]
                .tabs()
                .next()
                .map(|panel| app.panel_title(panel))
                .unwrap_or_else(|| "Workspace".into());
            let mut builder = egui::ViewportBuilder::default()
                .with_title(title)
                .with_inner_size([820.0, 520.0])
                .with_min_inner_size([360.0, 220.0]);
            if let Some(rect) = self.geometry.get(&index) {
                builder = builder.with_position(rect.min).with_inner_size(rect.size());
            }
            let mut closed = false;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of(("workspace", index)),
                builder,
                |ctx, class| {
                    closed = ctx.input(|input| input.viewport().close_requested());
                    if closed {
                        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    }
                    if let Some(rect) = ctx.input(|input| input.viewport().inner_rect) {
                        self.geometry.insert(index, rect);
                    }
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new("Workspace")
                            .id(egui::Id::new(("workspace-fallback", index)))
                            .show(ctx, |ui| self.show_surface(app, ui, surface));
                    } else {
                        egui::CentralPanel::default()
                            .frame(theme::frame(theme::BG))
                            .show(ctx, |ui| self.show_surface(app, ui, surface));
                    }
                },
            );
            if closed {
                self.close_surface(app, surface);
            }
        }
        if let Some(panel) = self.detach.take() {
            if let Some(location) = self.dock.find_tab(&panel) {
                self.dock.detach_tab(
                    location,
                    Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(820.0, 520.0)),
                );
            }
        }
        if let Some(position) = self.released.take() {
            if let Some((panel, source)) = self.drag.take() {
                self.drop_panel(&panel, source, position);
            }
        }
    }

    fn show_surface(&mut self, app: &mut MonitorApp, ui: &mut egui::Ui, surface: SurfaceIndex) {
        let Some(slot) = self.dock.get_surface_mut(surface) else {
            return;
        };
        let original = std::mem::replace(slot, Surface::Empty);
        let (tree, window) = match original {
            Surface::Main(tree) => (tree, None),
            Surface::Window(tree, window) => (tree, Some(window)),
            Surface::Empty => return,
        };
        let mut local = DockState::new(Vec::new());
        *local
            .get_surface_mut(SurfaceIndex::main())
            .expect("new dock always has a main surface") = Surface::Main(tree);
        let origin = ui
            .ctx()
            .input(|input| input.viewport().inner_rect.map(|rect| rect.min))
            .unwrap_or_default();
        let empty_target = ui.max_rect().translate(origin.to_vec2());
        let mut viewer = Viewer {
            app,
            layout: self,
            surface,
        };
        DockArea::new(&mut local)
            .id(egui::Id::new(("native-dock", surface.0)))
            .show_leaf_close_all_buttons(false)
            .show_leaf_collapse_buttons(false)
            .show_inside(ui, &mut viewer);
        for (index, node) in local.main_surface().iter().enumerate() {
            if node.is_leaf() {
                if let Some(rect) = node.rect() {
                    self.targets.push((
                        surface,
                        NodeIndex(index),
                        rect.translate(origin.to_vec2()),
                    ));
                }
            }
        }
        if local.main_surface().is_empty() {
            self.targets
                .push((surface, NodeIndex::root(), empty_target));
        }
        if self.drag.is_some() && ui.input(|input| input.pointer.any_released()) {
            self.released = ui
                .input(|input| {
                    input
                        .events
                        .iter()
                        .rev()
                        .find_map(|event| {
                            if let egui::Event::PointerButton {
                                pos,
                                pressed: false,
                                button: egui::PointerButton::Primary,
                                ..
                            } = event
                            {
                                Some(*pos)
                            } else {
                                None
                            }
                        })
                        .or(input.pointer.latest_pos())
                })
                .map(|position| position + origin.to_vec2());
        }
        let tree = std::mem::replace(local.main_surface_mut(), egui_dock::Tree::new(Vec::new()));
        *self
            .dock
            .get_surface_mut(surface)
            .expect("surface is reserved while rendering") = match window {
            Some(window) => Surface::Window(tree, window),
            None => Surface::Main(tree),
        };
    }

    fn drop_panel(&mut self, panel: &Panel, source: SurfaceIndex, position: egui::Pos2) {
        let Some(location) = self.dock.find_tab(panel) else {
            return;
        };
        if let Some((surface, node, rect)) = self
            .targets
            .iter()
            .rev()
            .find(|(_, _, rect)| rect.contains(position))
            .copied()
        {
            if surface == source {
                return;
            }
            if self.dock[surface].is_empty() {
                self.dock
                    .move_tab(location, TabDestination::EmptySurface(surface));
                return;
            }
            let rel = (position - rect.min) / rect.size();
            let insert = if rel.x < 0.2 {
                TabInsert::Split(egui_dock::Split::Left)
            } else if rel.x > 0.8 {
                TabInsert::Split(egui_dock::Split::Right)
            } else if rel.y < 0.2 {
                TabInsert::Split(egui_dock::Split::Above)
            } else if rel.y > 0.8 {
                TabInsert::Split(egui_dock::Split::Below)
            } else {
                TabInsert::Append
            };
            self.dock.move_tab(location, (surface, node, insert));
        } else {
            let surface = self.dock.detach_tab(
                location,
                Rect::from_min_size(position, egui::vec2(820.0, 520.0)),
            );
            self.geometry.insert(
                surface.0,
                Rect::from_min_size(position, egui::vec2(820.0, 520.0)),
            );
        }
    }

    /// Puts a panel back where the default layout keeps it: Run History and
    /// the trace in the upper tab bar, Details and Activity in the lower one,
    /// recreating that split when the other group is all that is left.
    fn return_home(&mut self, panel: Panel) {
        let lower = matches!(panel, Panel::Details | Panel::Activity);
        let (own, other) = if lower {
            (
                vec![Panel::Details, Panel::Activity],
                vec![Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis],
            )
        } else {
            (
                vec![Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis],
                vec![Panel::Details, Panel::Activity],
            )
        };
        // The first panel of each group goes before its sibling.
        let first = panel == own[0];
        let tree = self.dock.main_surface_mut();
        if let Some((node, _)) = own.iter().find_map(|sibling| tree.find_tab(sibling)) {
            if first {
                tree[node].insert_tab(TabIndex(0), panel);
            } else {
                tree[node].append_tab(panel);
            }
        } else if let Some((node, _)) = other.iter().find_map(|sibling| tree.find_tab(sibling)) {
            if lower {
                tree.split_below(node, 0.63, vec![panel]);
            } else {
                tree.split_above(node, 0.37, vec![panel]);
            }
        } else {
            tree.push_to_first_leaf(panel);
        }
    }

    fn close_surface(&mut self, app: &mut MonitorApp, surface: SurfaceIndex) {
        let panels: Vec<_> = self.dock[surface].tabs().cloned().collect();
        self.dock.remove_surface(surface);
        for panel in panels {
            if let Panel::Terminal(id) = panel {
                app.close_terminal_view(&id);
            } else {
                self.return_home(panel);
            }
        }
    }
}

struct Viewer<'a> {
    app: &'a mut MonitorApp,
    layout: &'a mut WorkspaceLayout,
    surface: SurfaceIndex,
}

impl TabViewer for Viewer<'_> {
    type Tab = Panel;
    fn title(&mut self, tab: &mut Panel) -> egui::WidgetText {
        self.app.panel_title(tab).into()
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
    fn closeable(&mut self, tab: &mut Panel) -> bool {
        matches!(tab, Panel::Terminal(_))
    }
    fn on_close(&mut self, tab: &mut Panel) -> bool {
        if let Panel::Terminal(id) = tab {
            self.app.close_terminal_view(id);
        }
        true
    }
    fn on_tab_button(&mut self, tab: &mut Panel, response: &egui::Response) {
        if response.drag_started()
            || (response.hovered() && response.ctx.input(|input| input.pointer.primary_pressed()))
        {
            self.layout.drag = Some((tab.clone(), self.surface));
        }
        response.clone().on_hover_text(self.app.panel_title(tab));
    }
    fn context_menu(&mut self, ui: &mut egui::Ui, tab: &mut Panel, _: SurfaceIndex, _: NodeIndex) {
        if ui.button("Detach").clicked() {
            self.layout.detach = Some(tab.clone());
            ui.close_menu();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_tabs(layout: &WorkspaceLayout, node: NodeIndex) -> Vec<Panel> {
        layout.dock.main_surface()[node]
            .tabs()
            .map(<[Panel]>::to_vec)
            .unwrap_or_default()
    }

    #[test]
    fn default_layout_puts_run_history_first_with_the_trace_open() {
        let layout = WorkspaceLayout::default();
        let top = NodeIndex::root().left();
        assert_eq!(
            leaf_tabs(&layout, top),
            [Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]
        );
        let egui_dock::Node::Leaf { tabs, active, .. } = &layout.dock.main_surface()[top] else {
            panic!("top node must hold tabs");
        };
        assert_eq!(tabs[active.0], Panel::Trace);
        assert_eq!(
            leaf_tabs(&layout, NodeIndex::root().right()),
            [Panel::Details, Panel::Activity]
        );
    }

    #[test]
    fn restore_replaces_a_layout_saved_before_versioning_once() {
        // A pre-versioning layout: the old default with Run History as a tab.
        let saved = WorkspaceLayout {
            version: 0,
            dock: DockState::new(vec![Panel::Trace, Panel::RunHistory]),
            ..WorkspaceLayout::default()
        };
        let restored = WorkspaceLayout::restore(Some(saved));
        assert_eq!(
            leaf_tabs(&restored, NodeIndex::root().left()),
            [Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]
        );
        // A current-version layout the user rearranged is kept as saved.
        let custom = WorkspaceLayout {
            dock: DockState::new(vec![Panel::Trace, Panel::RunHistory]),
            ..WorkspaceLayout::default()
        };
        let kept = WorkspaceLayout::restore(Some(custom));
        assert_eq!(
            leaf_tabs(&kept, NodeIndex::root()),
            [Panel::Trace, Panel::RunHistory]
        );
        assert!(WorkspaceLayout::restore(None).version >= 1);
    }

    #[test]
    fn returning_panels_go_home_instead_of_into_the_first_tab_bar() {
        // Details and Activity left in a window that was then closed.
        let mut layout = WorkspaceLayout::default();
        for panel in [Panel::Details, Panel::Activity] {
            let location = layout.dock.find_tab(&panel).expect("default panel");
            layout.dock.remove_tab(location);
        }
        layout.validate();
        let top = layout
            .dock
            .find_main_surface_tab(&Panel::Trace)
            .expect("trace stays")
            .0;
        let bottom = layout
            .dock
            .find_main_surface_tab(&Panel::Details)
            .expect("details returns")
            .0;
        assert_ne!(top, bottom, "Details must not join the trace's tab bar");
        assert_eq!(
            leaf_tabs(&layout, top),
            [Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]
        );
        assert_eq!(
            leaf_tabs(&layout, bottom),
            [Panel::Details, Panel::Activity]
        );

        // Every panel missing rebuilds the default arrangement, not one bar.
        let mut empty = WorkspaceLayout {
            dock: DockState::new(Vec::new()),
            ..WorkspaceLayout::default()
        };
        empty.validate();
        let top = empty.dock.find_main_surface_tab(&Panel::Trace).unwrap().0;
        let bottom = empty
            .dock
            .find_main_surface_tab(&Panel::Activity)
            .unwrap()
            .0;
        assert_eq!(
            leaf_tabs(&empty, top),
            [Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]
        );
        assert_eq!(leaf_tabs(&empty, bottom), [Panel::Details, Panel::Activity]);
    }

    #[test]
    fn restore_replaces_a_version_1_flattened_layout() {
        let flattened = WorkspaceLayout {
            version: 1,
            dock: DockState::new(vec![
                Panel::Trace,
                Panel::RunHistory,
                Panel::Details,
                Panel::Activity,
            ]),
            ..WorkspaceLayout::default()
        };
        let restored = WorkspaceLayout::restore(Some(flattened));
        assert_eq!(
            leaf_tabs(&restored, NodeIndex::root().left()),
            [Panel::RunHistory, Panel::Trace, Panel::StaticAnalysis]
        );
        assert_eq!(
            leaf_tabs(&restored, NodeIndex::root().right()),
            [Panel::Details, Panel::Activity]
        );
    }

    #[test]
    fn detach_and_drag_merge_keep_each_logical_panel_once() {
        let mut layout = WorkspaceLayout::default();
        let trace = Panel::Trace;
        layout.drop_panel(&trace, SurfaceIndex::main(), egui::pos2(1400.0, 200.0));
        let detached = layout
            .dock
            .find_tab(&trace)
            .expect("trace survives detachment")
            .0;
        assert!(!detached.is_main());
        layout.targets.push((
            SurfaceIndex::main(),
            NodeIndex(1),
            Rect::from_min_size(egui::pos2(200.0, 100.0), egui::vec2(800.0, 500.0)),
        ));
        layout.drop_panel(&trace, detached, egui::pos2(600.0, 350.0));
        assert!(layout
            .dock
            .find_tab(&trace)
            .expect("trace docked")
            .0
            .is_main());
        for panel in [
            Panel::Trace,
            Panel::RunHistory,
            Panel::Details,
            Panel::Activity,
        ] {
            assert_eq!(
                layout
                    .dock
                    .iter_all_tabs()
                    .filter(|(_, tab)| **tab == panel)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn terminal_drag_preserves_stable_owner_and_other_surface() {
        let mut layout = WorkspaceLayout::default();
        let first = Panel::Terminal("first".into());
        let second = Panel::Terminal("second".into());
        let source = layout.dock.add_window(vec![first.clone()]);
        let other = layout.dock.add_window(vec![second.clone()]);
        layout.targets.push((
            SurfaceIndex::main(),
            NodeIndex(1),
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        layout.drop_panel(&first, source, egui::pos2(400.0, 250.0));
        assert!(layout.dock.find_tab(&first).unwrap().0.is_main());
        assert_eq!(layout.dock.find_tab(&second).unwrap().0, other);
        assert_eq!(
            layout
                .dock
                .iter_all_tabs()
                .filter(|(_, tab)| **tab == first)
                .count(),
            1
        );
    }

    #[test]
    fn restored_layout_removes_stale_terminals_and_duplicate_panels() {
        let mut layout = WorkspaceLayout::default();
        layout
            .dock
            .add_window(vec![Panel::Trace, Panel::Terminal("past".into())]);
        layout.validate();
        assert_eq!(layout.dock.iter_all_tabs().count(), 5);
        assert_eq!(
            layout
                .dock
                .iter_all_tabs()
                .filter(|(_, tab)| **tab == Panel::Trace)
                .count(),
            1
        );
    }

    #[test]
    fn analysis_tab_is_added_to_saved_custom_layout_and_detaches_without_reset() {
        let mut custom = WorkspaceLayout::default();
        let trace = custom.dock.find_tab(&Panel::Trace).unwrap();
        let detached_trace = custom.dock.detach_tab(
            trace,
            Rect::from_min_size(egui::pos2(40.0, 60.0), egui::vec2(700.0, 400.0)),
        );
        let analysis = custom.dock.find_tab(&Panel::StaticAnalysis).unwrap();
        custom.dock.remove_tab(analysis);
        let mut restored = WorkspaceLayout::restore(Some(custom));
        restored.validate();
        assert_eq!(
            restored.dock.find_tab(&Panel::Trace).unwrap().0,
            detached_trace
        );
        let analysis = restored.dock.find_tab(&Panel::StaticAnalysis).unwrap();
        let detached_analysis = restored.dock.detach_tab(
            analysis,
            Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(820.0, 520.0)),
        );
        assert_ne!(detached_analysis, detached_trace);
        restored.targets.push((
            SurfaceIndex::main(),
            NodeIndex(1),
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        restored.drop_panel(
            &Panel::StaticAnalysis,
            detached_analysis,
            egui::pos2(400.0, 250.0),
        );
        assert!(restored
            .dock
            .find_tab(&Panel::StaticAnalysis)
            .unwrap()
            .0
            .is_main());
        assert_eq!(
            restored.dock.find_tab(&Panel::Trace).unwrap().0,
            detached_trace
        );
        assert_eq!(
            restored
                .dock
                .iter_all_tabs()
                .filter(|(_, panel)| **panel == Panel::StaticAnalysis)
                .count(),
            1
        );
    }
}
