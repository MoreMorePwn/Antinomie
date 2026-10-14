//! A single dock tree rendered by moving each surface into its native viewport.
use crate::{app::MonitorApp, theme};
use antinomie_monitor_core::AnalysisKind;
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
    Network,
    Memory,
    CoreDump,
    Triage,
    StaticAnalysis,
    AnalysisSection {
        report_id: String,
        kind: AnalysisKind,
    },
    Summary,
    RunHistory,
    Details,
    Activity,
    Terminal(String),
}

impl Panel {
    pub(crate) fn title(&self) -> &str {
        match self {
            Self::Trace => "Syscall Trace",
            Self::Network => "Network",
            Self::Memory => "Memory",
            Self::CoreDump => "Core dumps",
            Self::Triage => "Triage",
            Self::StaticAnalysis => "Static Analysis",
            Self::AnalysisSection { kind, .. } => kind.label(),
            Self::Summary => "Summary",
            Self::RunHistory => "Run History",
            Self::Details => "Details",
            Self::Activity => "Activity",
            Self::Terminal(_) => "Terminal",
        }
    }
}

/// Which main tab the bottom Details panel follows: the syscall trace, the
/// network panel or the memory panel. When only one of them is on screen it
/// wins; when several are (split or detached), the one clicked last.
#[derive(Default)]
pub(crate) struct DetailsFollow {
    followed: usize,
    /// Pass of the main window in which each followed panel was last drawn.
    drawn: [Option<u64>; 4],
}

/// What the Details panel shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetailsOf {
    Syscall,
    Packet,
    MemoryRow,
    History,
}

impl DetailsFollow {
    const SIDES: [DetailsOf; 4] = [
        DetailsOf::Syscall,
        DetailsOf::Packet,
        DetailsOf::MemoryRow,
        DetailsOf::History,
    ];

    fn side(panel: &Panel) -> Option<usize> {
        match panel {
            Panel::Trace => Some(0),
            Panel::Network => Some(1),
            Panel::Memory => Some(2),
            Panel::RunHistory => Some(3),
            _ => None,
        }
    }

    /// `panel` was drawn into `ui` this pass.
    pub(crate) fn drawn(&mut self, ui: &egui::Ui, panel: &Panel) {
        let Some(side) = Self::side(panel) else {
            return;
        };
        let now = ui.ctx().cumulative_pass_nr_for(egui::ViewportId::ROOT);
        self.drawn[side] = Some(now);
        // Alone on screen: it stays followed after it is hidden again (by
        // Run History, say).
        let alone = (0..self.drawn.len())
            .filter(|other| *other != side)
            .all(|other| self.drawn[other].is_none_or(|pass| pass + 1 < now));
        let rect = ui.max_rect();
        if alone
            || ui.input(|input| {
                input.pointer.any_pressed()
                    && input
                        .pointer
                        .interact_pos()
                        .is_some_and(|pos| rect.contains(pos))
            })
        {
            self.followed = side;
        }
    }

    /// The user chose `panel`'s tab.
    pub(crate) fn chose(&mut self, panel: &Panel) {
        if let Some(side) = Self::side(panel) {
            self.followed = side;
        }
    }

    /// What Details show now.
    pub(crate) fn of(&self, ctx: &egui::Context) -> DetailsOf {
        let now = ctx.cumulative_pass_nr_for(egui::ViewportId::ROOT);
        let visible: Vec<usize> = (0..self.drawn.len())
            .filter(|side| self.drawn[*side].is_some_and(|pass| pass + 1 >= now))
            .collect();
        match visible.as_slice() {
            [only] => Self::SIDES[*only],
            _ => Self::SIDES[self.followed],
        }
    }
}

/// Arrangement compatibility. Versions before 3 reset obsolete flattened
/// layouts; version 4 adds Summary while preserving the version-3 dock tree.
const LAYOUT_VERSION: u32 = 5;

#[derive(Serialize, Deserialize)]
pub(crate) struct WorkspaceLayout {
    /// Absent (0) in layouts saved before versioning.
    #[serde(default)]
    version: u32,
    dock: DockState<Panel>,
    /// Outer/chrome origin plus inner/content size, in egui points.
    geometry: BTreeMap<usize, Rect>,
    #[serde(skip)]
    native_builders: BTreeMap<usize, egui::ViewportBuilder>,
    #[serde(skip)]
    drag: Option<(Panel, SurfaceIndex)>,
    #[serde(skip)]
    targets: Vec<(SurfaceIndex, NodeIndex, Rect)>,
    #[serde(skip)]
    target_headers: Vec<(SurfaceIndex, NodeIndex, Rect)>,
    #[serde(skip)]
    released: Option<(SurfaceIndex, egui::Pos2)>,
    #[serde(skip)]
    detach: Option<Panel>,
    #[serde(skip)]
    dock_back: Option<Panel>,
    #[serde(skip)]
    cancel_drag: bool,
}

impl Default for WorkspaceLayout {
    fn default() -> Self {
        // Summary opens first, immediately to the left of Run History.
        let mut dock = DockState::new(vec![
            Panel::Summary,
            Panel::RunHistory,
            Panel::Trace,
            Panel::Network,
            Panel::Memory,
            Panel::CoreDump,
            Panel::Triage,
            Panel::StaticAnalysis,
        ]);
        dock.set_active_tab((SurfaceIndex::main(), NodeIndex::root(), TabIndex(0)));
        // The work area gets most of the height; details sit below.
        dock.main_surface_mut().split_below(
            NodeIndex::root(),
            0.72,
            vec![Panel::Details, Panel::Activity],
        );
        Self {
            version: LAYOUT_VERSION,
            dock,
            geometry: BTreeMap::new(),
            native_builders: BTreeMap::new(),
            drag: None,
            targets: Vec::new(),
            target_headers: Vec::new(),
            released: None,
            detach: None,
            dock_back: None,
            cancel_drag: false,
        }
    }
}

impl WorkspaceLayout {
    /// The saved layout, unless it predates the current default arrangement.
    pub(crate) fn restore(saved: Option<Self>) -> Self {
        let Some(mut layout) = saved.filter(|layout| layout.version >= 3) else {
            return Self::default();
        };
        if layout.version < LAYOUT_VERSION {
            // Keep the user's splits and native windows from 0.5.0. Place the
            // new tab beside Run History in whichever surface owns it.
            if layout.dock.find_tab(&Panel::Summary).is_none() {
                if let Some((surface, node, tab)) = layout.dock.find_tab(&Panel::RunHistory) {
                    layout.dock[surface][node].insert_tab(tab, Panel::Summary);
                } else {
                    layout.return_home(Panel::Summary);
                }
            }
            if layout.version < 5 && layout.dock.find_tab(&Panel::Triage).is_none() {
                if let Some((surface, node, tab)) = layout.dock.find_tab(&Panel::Trace) {
                    layout.dock[surface][node].insert_tab(tab, Panel::Triage);
                } else {
                    layout.return_home(Panel::Triage);
                }
            }
            layout.focus(Panel::Summary);
            layout.version = LAYOUT_VERSION;
        }
        layout
    }

    pub(crate) fn validate(&mut self) {
        let mut seen = Vec::new();
        // Retain each tree in place. DockState::retain_tabs compacts surface
        // indices, which would associate saved geometry with another window.
        for index in 0..self.dock.surfaces_count() {
            if self.dock.is_surface_valid(SurfaceIndex(index)) {
                self.dock[SurfaceIndex(index)].retain_tabs(|tab| {
                    if matches!(tab, Panel::Terminal(_) | Panel::AnalysisSection { .. })
                        || seen.contains(tab)
                    {
                        false
                    } else {
                        seen.push(tab.clone());
                        true
                    }
                });
            }
        }
        self.remove_empty_windows();
        for panel in [
            Panel::Summary,
            Panel::RunHistory,
            Panel::Trace,
            Panel::Network,
            Panel::Memory,
            Panel::CoreDump,
            Panel::Triage,
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

    fn remove_empty_windows(&mut self) {
        // An empty root node can remain allocated, so test tabs rather than
        // Tree::is_empty. Remove in reverse without shifting retained indices.
        for index in (1..self.dock.surfaces_count()).rev() {
            let surface = SurfaceIndex(index);
            if self.dock.is_surface_valid(surface) && self.dock[surface].tabs().next().is_none() {
                self.dock.remove_surface(surface);
                self.geometry.remove(&index);
                self.native_builders.remove(&index);
            }
        }
    }

    pub(crate) fn focus(&mut self, panel: Panel) {
        if let Some((surface, node, tab)) = self.dock.find_tab(&panel) {
            self.dock.set_active_tab((surface, node, tab));
            self.dock.set_focused_node_and_surface((surface, node));
        }
    }

    pub(crate) fn show(&mut self, app: &mut MonitorApp, ctx: &egui::Context) {
        self.targets.clear();
        self.target_headers.clear();
        self.native_builders
            .retain(|index, _| self.dock.is_surface_valid(SurfaceIndex(*index)));
        self.cancel_drag = false;
        for (id, open) in app.terminal_views() {
            let panel = Panel::Terminal(id);
            if open && self.dock.find_tab(&panel).is_none() {
                let surface = self.dock.add_window(vec![panel]);
                self.geometry.remove(&surface.0);
                self.native_builders.remove(&surface.0);
            } else if !open {
                if let Some(location) = self.dock.find_tab(&panel) {
                    self.dock.remove_tab(location);
                }
            }
        }
        self.remove_empty_windows();
        egui::CentralPanel::default()
            .frame(theme::frame(theme::bg()))
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
            let builder = self.native_builder(index, title);
            let mut closed = false;
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of(("workspace", index)),
                builder,
                |ctx, class| {
                    closed = ctx.input(|input| input.viewport().close_requested());
                    if closed {
                        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    }
                    if class != egui::ViewportClass::Embedded {
                        ctx.input(|input| self.remember_geometry(index, input.viewport()));
                    }
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new("Workspace")
                            .id(egui::Id::new(("workspace-fallback", index)))
                            .show(ctx, |ui| self.show_surface(app, ui, surface));
                    } else {
                        egui::CentralPanel::default()
                            .frame(theme::frame(theme::bg()))
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
                let surface = self.dock.detach_tab(
                    location,
                    Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(820.0, 520.0)),
                );
                self.geometry.insert(
                    surface.0,
                    Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(820.0, 520.0)),
                );
                self.native_builders.remove(&surface.0);
            }
        }
        if let Some(panel) = self.dock_back.take() {
            self.dock_panel(panel);
        }
        self.finish_drag();
        for (report_id, kind) in app.take_analysis_sections() {
            let panel = Panel::AnalysisSection { report_id, kind };
            if self.dock.find_tab(&panel).is_none() {
                let surface = self.dock.add_window(vec![panel.clone()]);
                self.geometry.remove(&surface.0);
                self.native_builders.remove(&surface.0);
            }
            self.focus(panel.clone());
            if let Some((surface, _, _)) = self.dock.find_tab(&panel) {
                if !surface.is_main() {
                    ctx.send_viewport_cmd_to(
                        egui::ViewportId::from_hash_of(("workspace", surface.0)),
                        egui::ViewportCommand::Focus,
                    );
                }
            }
        }
        let report_ids: Vec<_> = self
            .dock
            .iter_all_tabs()
            .filter_map(|(_, panel)| match panel {
                Panel::AnalysisSection { report_id, .. } => Some(report_id.clone()),
                _ => None,
            })
            .collect();
        app.retain_analysis_windows(&report_ids);
    }

    fn native_builder(&mut self, index: usize, title: String) -> egui::ViewportBuilder {
        // Observed geometry is persistence data, not a placement command every frame.
        let builder = self.native_builders.entry(index).or_insert_with(|| {
            let mut builder = egui::ViewportBuilder::default()
                .with_inner_size([820.0, 520.0])
                .with_min_inner_size([360.0, 220.0]);
            if let Some(rect) = self.geometry.get(&index) {
                builder = builder.with_position(rect.min).with_inner_size(rect.size());
            }
            builder
        });
        builder.clone().with_title(title)
    }

    fn remember_geometry(&mut self, index: usize, viewport: &egui::ViewportInfo) {
        if let (Some(outer), Some(inner)) = (viewport.outer_rect, viewport.inner_rect) {
            // with_position sets the outer origin; reusing the inner origin drifts.
            let rect = Rect::from_min_size(outer.min, inner.size());
            if rect.is_finite() && rect.width() >= 200.0 && rect.height() >= 100.0 {
                self.geometry.insert(index, rect);
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
        let dock_style = theme::dock_style(ui.style());
        DockArea::new(&mut local)
            .id(egui::Id::new(("native-dock", surface.0)))
            .style(dock_style)
            .draggable_tabs(false)
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
                    if let egui_dock::Node::Leaf { viewport, .. } = node {
                        let header =
                            Rect::from_min_max(rect.min, egui::pos2(rect.max.x, viewport.min.y));
                        self.target_headers.push((
                            surface,
                            NodeIndex(index),
                            header.translate(origin.to_vec2()),
                        ));
                    }
                }
            }
        }
        if local.main_surface().is_empty() {
            self.targets
                .push((surface, NodeIndex::root(), empty_target));
        }
        if let Some((_, source)) = self.drag.as_ref() {
            if let Some(position) = ui.input(primary_release) {
                if self.released.is_none() || *source == surface {
                    self.released = Some((surface, position + origin.to_vec2()));
                }
            }
            if *source == surface
                && self.released.is_none()
                && ui.input(|input| !input.pointer.primary_down())
            {
                self.cancel_drag = true;
            }
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
            if self.dock[surface].is_empty() {
                self.dock
                    .move_tab(location, TabDestination::EmptySurface(surface));
                return;
            }
            let rel = (position - rect.min) / rect.size();
            let on_header =
                self.target_headers
                    .iter()
                    .any(|(header_surface, header_node, header)| {
                        *header_surface == surface
                            && *header_node == node
                            && header.contains(position)
                    });
            if on_header && location.0 == surface && location.1 == node {
                self.focus(panel.clone());
                return;
            }
            let insert = if on_header {
                TabInsert::Append
            } else if rel.x < 0.2 {
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
        } else if !location.0.is_main() && self.dock[location.0].num_tabs() == 1 {
            let size = self
                .geometry
                .get(&location.0 .0)
                .map(Rect::size)
                .unwrap_or(egui::vec2(820.0, 520.0));
            self.geometry
                .insert(location.0 .0, Rect::from_min_size(position, size));
            if let Some(builder) = self.native_builders.get_mut(&location.0 .0) {
                builder.position = Some(position);
            }
            if let Some(window) = self.dock.get_window_state_mut(location.0) {
                window.set_position(position);
            }
        } else {
            let surface = self.dock.detach_tab(
                location,
                Rect::from_min_size(position, egui::vec2(820.0, 520.0)),
            );
            self.geometry.insert(
                surface.0,
                Rect::from_min_size(position, egui::vec2(820.0, 520.0)),
            );
            self.native_builders.remove(&surface.0);
        }
        if !self.dock.is_surface_valid(source) {
            self.geometry.remove(&source.0);
            self.native_builders.remove(&source.0);
        }
    }

    fn dock_panel(&mut self, panel: Panel) {
        let Some(location) = self.dock.find_tab(&panel) else {
            return;
        };
        if location.0.is_main() {
            return;
        }
        let home = if matches!(panel, Panel::Details | Panel::Activity) {
            [Panel::Details, Panel::Activity]
        } else {
            [Panel::Trace, Panel::RunHistory]
        };
        if self.dock.main_surface().is_empty() {
            self.dock
                .move_tab(location, TabDestination::EmptySurface(SurfaceIndex::main()));
        } else {
            let target = home
                .iter()
                .find_map(|tab| self.dock.find_main_surface_tab(tab))
                .map(|(node, _)| node)
                .or_else(|| {
                    self.dock
                        .main_surface()
                        .iter()
                        .enumerate()
                        .find(|(_, node)| node.is_leaf())
                        .map(|(index, _)| NodeIndex(index))
                });
            let Some(target) = target else {
                return;
            };
            self.dock
                .move_tab(location, (SurfaceIndex::main(), target, TabInsert::Append));
        }
        self.focus(panel);
        if !self.dock.is_surface_valid(location.0) {
            self.geometry.remove(&location.0 .0);
            self.native_builders.remove(&location.0 .0);
        }
    }

    fn finish_drag(&mut self) {
        if let Some((_, position)) = self.released.take() {
            if let Some((panel, source)) = self.drag.take() {
                self.drop_panel(&panel, source, position);
            }
        } else if self.cancel_drag {
            self.drag = None;
        }
        self.cancel_drag = false;
    }

    /// Puts a panel back where the default layout keeps it: Run History and
    /// the trace in the upper tab bar, Details and Activity in the lower one,
    /// recreating that split when the other group is all that is left.
    fn return_home(&mut self, panel: Panel) {
        let lower = matches!(panel, Panel::Details | Panel::Activity);
        let (own, other) = if lower {
            (
                vec![Panel::Details, Panel::Activity],
                vec![
                    Panel::Summary,
                    Panel::RunHistory,
                    Panel::Trace,
                    Panel::Network,
                    Panel::Memory,
                    Panel::CoreDump,
                    Panel::Triage,
                    Panel::StaticAnalysis,
                ],
            )
        } else {
            (
                vec![
                    Panel::Summary,
                    Panel::RunHistory,
                    Panel::Trace,
                    Panel::Network,
                    Panel::Memory,
                    Panel::CoreDump,
                    Panel::Triage,
                    Panel::StaticAnalysis,
                ],
                vec![Panel::Details, Panel::Activity],
            )
        };
        // The first panel of each group goes before its sibling.
        let first = panel == own[0];
        let tree = self.dock.main_surface_mut();
        let beside = match panel {
            Panel::Summary => Some((Panel::RunHistory, false)),
            Panel::RunHistory => Some((Panel::Summary, true)),
            _ => None,
        };
        if let Some((sibling, after)) = beside {
            if let Some((node, tab)) = tree.find_tab(&sibling) {
                tree[node].insert_tab(TabIndex(tab.0 + usize::from(after)), panel);
                return;
            }
        }
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
        self.geometry.remove(&surface.0);
        self.native_builders.remove(&surface.0);
        for panel in panels {
            if let Panel::Terminal(id) = panel {
                app.close_terminal_view(&id);
            } else if matches!(panel, Panel::AnalysisSection { .. }) {
                continue;
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
        theme::tab_title(&self.app.panel_title(tab)).into()
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
        matches!(tab, Panel::Terminal(_) | Panel::AnalysisSection { .. })
    }
    fn on_close(&mut self, tab: &mut Panel) -> bool {
        if let Panel::Terminal(id) = tab {
            self.app.close_terminal_view(id);
        }
        true
    }
    fn on_tab_button(&mut self, tab: &mut Panel, response: &egui::Response) {
        if response.drag_started_by(egui::PointerButton::Primary) {
            self.layout.drag = Some((tab.clone(), self.surface));
        }
        if response.clicked() {
            self.app.details_follow.chose(tab);
        }
        response.clone().on_hover_text(self.app.panel_title(tab));
    }
    fn context_menu(&mut self, ui: &mut egui::Ui, tab: &mut Panel, _: SurfaceIndex, _: NodeIndex) {
        if !self.surface.is_main()
            && ui
                .button("Dock")
                .on_hover_text("Move this tab into the main window")
                .clicked()
        {
            self.layout.dock_back = Some(tab.clone());
            ui.close_menu();
        }
        if ui.button("Detach").clicked() {
            self.layout.detach = Some(tab.clone());
            ui.close_menu();
        }
    }
}

fn primary_release(input: &egui::InputState) -> Option<egui::Pos2> {
    input.events.iter().rev().find_map(|event| match event {
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed: false,
            ..
        } => Some(*pos),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_geometry_does_not_drive_live_placement() {
        let mut layout = WorkspaceLayout::default();
        let source = layout
            .dock
            .add_window(vec![Panel::Terminal("placement".into())]);
        let initial = Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(650.0, 450.0));
        layout.geometry.insert(source.0, initial);
        let first = layout.native_builder(source.0, "First".into());
        let observed = Rect::from_min_size(egui::pos2(200.0, 200.0), egui::vec2(700.0, 500.0));
        layout.remember_geometry(
            source.0,
            &egui::ViewportInfo {
                outer_rect: Some(observed),
                inner_rect: Some(observed),
                ..Default::default()
            },
        );
        let next = layout.native_builder(source.0, "Updated title".into());
        assert_eq!(next.position, first.position);
        assert_eq!(next.inner_size, first.inner_size);
        assert_eq!(next.title.as_deref(), Some("Updated title"));
        assert_eq!(layout.geometry[&source.0], observed);
        #[derive(Default)]
        struct LayoutStorage(Option<String>);
        impl eframe::Storage for LayoutStorage {
            fn get_string(&self, _: &str) -> Option<String> {
                self.0.clone()
            }
            fn set_string(&mut self, _: &str, value: String) {
                self.0 = Some(value);
            }
            fn flush(&mut self) {}
        }
        let mut storage = LayoutStorage::default();
        eframe::set_value(&mut storage, "workspace_layout", &layout);
        let mut restored: WorkspaceLayout =
            eframe::get_value(&storage, "workspace_layout").unwrap();
        assert!(restored.native_builders.is_empty());
        let reopened = restored.native_builder(source.0, "Reopened".into());
        assert_eq!(reopened.position, Some(observed.min));
        assert_eq!(reopened.inner_size, Some(observed.size()));
    }

    #[test]
    fn stale_move_observation_cannot_rewind_requested_position() {
        let mut layout = WorkspaceLayout::default();
        let panel = Panel::Terminal("move-ack".into());
        let source = layout.dock.add_window(vec![panel.clone()]);
        let old = Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(650.0, 450.0));
        layout.geometry.insert(source.0, old);
        layout.native_builder(source.0, "Terminal".into());
        let requested = egui::pos2(1100.0, 500.0);
        layout.drop_panel(&panel, source, requested);
        for _ in 0..5 {
            layout.remember_geometry(
                source.0,
                &egui::ViewportInfo {
                    outer_rect: Some(old),
                    inner_rect: Some(old),
                    ..Default::default()
                },
            );
            assert_eq!(
                layout.native_builder(source.0, "Terminal".into()).position,
                Some(requested)
            );
        }
    }

    #[test]
    fn own_header_drop_preserves_the_tab_group() {
        for x in [30.0, 400.0, 780.0] {
            let mut layout = WorkspaceLayout::default();
            let node = layout.dock.find_main_surface_tab(&Panel::Trace).unwrap().0;
            let before = leaf_tabs(&layout, node);
            let count = layout.dock.main_surface().len();
            layout.targets.push((
                SurfaceIndex::main(),
                node,
                Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
            ));
            layout.target_headers.push((
                SurfaceIndex::main(),
                node,
                Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 40.0)),
            ));
            layout.drop_panel(&Panel::Trace, SurfaceIndex::main(), egui::pos2(x, 20.0));
            assert_eq!(leaf_tabs(&layout, node), before);
            assert_eq!(layout.dock.main_surface().len(), count);
        }
    }

    #[test]
    fn another_header_drop_appends_instead_of_splitting() {
        let mut layout = WorkspaceLayout::default();
        let node = layout
            .dock
            .find_main_surface_tab(&Panel::Details)
            .unwrap()
            .0;
        let count = layout.dock.main_surface().len();
        layout.targets.push((
            SurfaceIndex::main(),
            node,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        layout.target_headers.push((
            SurfaceIndex::main(),
            node,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 40.0)),
        ));
        layout.drop_panel(&Panel::Trace, SurfaceIndex::main(), egui::pos2(30.0, 20.0));
        assert_eq!(
            leaf_tabs(&layout, node),
            [Panel::Details, Panel::Activity, Panel::Trace]
        );
        assert_eq!(layout.dock.main_surface().len(), count);
    }

    #[test]
    fn body_edge_drop_still_splits_a_group() {
        let mut layout = WorkspaceLayout::default();
        let node = layout.dock.find_main_surface_tab(&Panel::Trace).unwrap().0;
        layout.targets.push((
            SurfaceIndex::main(),
            node,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        layout.target_headers.push((
            SurfaceIndex::main(),
            node,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 40.0)),
        ));
        layout.drop_panel(&Panel::Trace, SurfaceIndex::main(), egui::pos2(400.0, 80.0));
        assert_ne!(
            layout.dock.find_main_surface_tab(&Panel::Trace).unwrap().0,
            node
        );
        assert!(layout.dock.main_surface()[node].is_parent());
    }

    #[test]
    fn moving_a_lone_detached_tab_preserves_its_surface_and_size() {
        let mut layout = WorkspaceLayout::default();
        let panel = Panel::Terminal("stable-window".into());
        let source = layout.dock.add_window(vec![panel.clone()]);
        let size = egui::vec2(650.0, 450.0);
        layout.geometry.insert(
            source.0,
            Rect::from_min_size(egui::pos2(100.0, 100.0), size),
        );
        let count = layout.dock.surfaces_count();
        for position in [egui::pos2(1400.0, 200.0), egui::pos2(1500.0, 300.0)] {
            layout.drop_panel(&panel, source, position);
            assert_eq!(layout.dock.find_tab(&panel).unwrap().0, source);
            assert_eq!(layout.dock.surfaces_count(), count);
            assert_eq!(
                layout.geometry[&source.0],
                Rect::from_min_size(position, size)
            );
        }
    }

    #[test]
    fn restoring_layout_discards_ephemeral_analysis_views_not_saved_reports() {
        let mut layout = WorkspaceLayout::default();
        layout.dock.add_window(vec![Panel::AnalysisSection {
            report_id: "old-report".into(),
            kind: AnalysisKind::Strings,
        }]);
        layout.validate();
        assert!(!layout
            .dock
            .iter_all_tabs()
            .any(|(_, panel)| matches!(panel, Panel::AnalysisSection { .. })));
        assert!(layout.dock.find_tab(&Panel::StaticAnalysis).is_some());
    }

    #[test]
    fn only_an_explicit_primary_release_can_commit_a_tab_drop() {
        let position = egui::pos2(400.0, 200.0);
        let mut input = egui::InputState::default();
        input.events = vec![
            egui::Event::PointerMoved(position),
            egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Secondary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            },
        ];
        assert_eq!(primary_release(&input), None);
        input.events.push(egui::Event::PointerButton {
            pos: position,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        });
        assert_eq!(primary_release(&input), Some(position));
    }

    #[test]
    fn dragging_between_main_window_leaves_moves_the_tab() {
        let mut layout = WorkspaceLayout::default();
        let destination = layout
            .dock
            .find_main_surface_tab(&Panel::Details)
            .unwrap()
            .0;
        layout.targets.push((
            SurfaceIndex::main(),
            destination,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        layout.drop_panel(
            &Panel::Trace,
            SurfaceIndex::main(),
            egui::pos2(400.0, 250.0),
        );
        assert_eq!(
            layout.dock.find_main_surface_tab(&Panel::Trace).unwrap().0,
            destination
        );
    }

    #[test]
    fn dock_action_merges_a_detached_terminal_without_losing_other_tabs() {
        let mut layout = WorkspaceLayout::default();
        let terminal = Panel::Terminal("dock-test".into());
        let surface = layout.dock.add_window(vec![terminal.clone()]);
        layout.geometry.insert(
            surface.0,
            Rect::from_min_size(egui::pos2(100.0, 80.0), egui::vec2(820.0, 520.0)),
        );
        let count = layout.dock.iter_all_tabs().count();
        layout.dock_panel(terminal.clone());
        assert!(layout.dock.find_tab(&terminal).unwrap().0.is_main());
        assert_eq!(layout.dock.iter_all_tabs().count(), count);
        assert!(!layout.geometry.contains_key(&surface.0));
    }

    #[test]
    fn dock_action_finds_a_leaf_when_preferred_home_tabs_are_detached() {
        let mut layout = WorkspaceLayout::default();
        for panel in [Panel::Trace, Panel::RunHistory] {
            let location = layout.dock.find_tab(&panel).unwrap();
            layout.dock.detach_tab(
                location,
                Rect::from_min_size(egui::pos2(100.0, 80.0), egui::vec2(820.0, 520.0)),
            );
        }
        layout.dock.main_surface_mut().split_right(
            NodeIndex::root(),
            0.5,
            vec![Panel::Terminal("main-stays".into())],
        );
        assert!(!layout.dock.main_surface()[NodeIndex::root()].is_leaf());
        let terminal = Panel::Terminal("dock-fallback".into());
        layout.dock.add_window(vec![terminal.clone()]);
        layout.dock_panel(terminal.clone());
        let (surface, node, _) = layout.dock.find_tab(&terminal).unwrap();
        assert!(surface.is_main());
        assert!(layout.dock.main_surface()[node].is_leaf());
    }

    #[test]
    fn destination_release_wins_over_earlier_source_focus_loss() {
        let mut layout = WorkspaceLayout::default();
        let terminal = Panel::Terminal("release-target".into());
        let source = layout.dock.add_window(vec![terminal.clone()]);
        let target = layout.dock.find_main_surface_tab(&Panel::Trace).unwrap().0;
        layout.targets.push((
            SurfaceIndex::main(),
            target,
            Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 500.0)),
        ));
        layout.drag = Some((terminal.clone(), source));
        layout.cancel_drag = true;
        layout.released = Some((SurfaceIndex::main(), egui::pos2(400.0, 250.0)));
        layout.finish_drag();
        assert!(layout.dock.find_tab(&terminal).unwrap().0.is_main());
        assert!(layout.drag.is_none());
        assert!(!layout.cancel_drag);
    }

    #[test]
    fn source_focus_loss_without_a_release_cancels_instead_of_dropping() {
        let mut layout = WorkspaceLayout::default();
        let before = layout.dock.iter_all_tabs().count();
        layout.drag = Some((Panel::Trace, SurfaceIndex::main()));
        layout.cancel_drag = true;
        layout.finish_drag();
        assert!(layout.drag.is_none());
        assert_eq!(layout.dock.iter_all_tabs().count(), before);
        assert!(layout.dock.find_tab(&Panel::Trace).unwrap().0.is_main());
    }

    #[test]
    fn decorated_viewport_updates_do_not_move_or_grow_the_window() {
        let mut layout = WorkspaceLayout::default();
        let mut outer_origin = egui::pos2(100.0, 80.0);
        let mut inner_size = egui::vec2(820.0, 520.0);
        let mut builder = egui::ViewportBuilder::default()
            .with_title("Terminal")
            .with_position(outer_origin)
            .with_inner_size(inner_size);
        for frame in 0..64 {
            if frame == 32 {
                outer_origin = egui::pos2(-240.0, 160.0);
                inner_size = egui::vec2(740.0, 460.0);
            }
            let viewport = egui::ViewportInfo {
                outer_rect: Some(Rect::from_min_size(
                    outer_origin,
                    inner_size + egui::vec2(16.0, 36.0),
                )),
                inner_rect: Some(Rect::from_min_size(
                    outer_origin + egui::vec2(8.0, 28.0),
                    inner_size,
                )),
                ..Default::default()
            };
            layout.remember_geometry(1, &viewport);
            let next = layout.native_builder(1, "Terminal".into());
            assert_eq!(next.position, Some(egui::pos2(100.0, 80.0)));
            assert_eq!(next.inner_size, Some(egui::vec2(820.0, 520.0)));
            assert_eq!(
                layout.geometry[&1],
                Rect::from_min_size(outer_origin, inner_size)
            );
            let (commands, recreate) = builder.patch(next);
            assert!(!recreate);
            assert!(!commands.iter().any(|command| matches!(
                command,
                egui::ViewportCommand::OuterPosition(_) | egui::ViewportCommand::InnerSize(_)
            )));
        }
    }

    #[test]
    fn missing_outer_position_never_substitutes_the_inner_origin() {
        let mut layout = WorkspaceLayout::default();
        let inner = Rect::from_min_size(egui::pos2(108.0, 108.0), egui::vec2(820.0, 520.0));
        layout.remember_geometry(
            1,
            &egui::ViewportInfo {
                inner_rect: Some(inner),
                ..Default::default()
            },
        );
        assert!(!layout.geometry.contains_key(&1));
        let previous = Rect::from_min_size(egui::pos2(100.0, 80.0), inner.size());
        layout.geometry.insert(1, previous);
        layout.remember_geometry(1, &egui::ViewportInfo::default());
        assert_eq!(layout.geometry[&1], previous);
    }

    #[test]
    fn saved_geometry_preserves_outer_origin_and_inner_size() {
        let mut layout = WorkspaceLayout::default();
        let surface = layout.dock.add_window(vec![Panel::Terminal("test".into())]);
        let rect = Rect::from_min_size(egui::pos2(-240.0, 160.0), egui::vec2(740.0, 460.0));
        layout.geometry.insert(surface.0, rect);
        let encoded = serde_json::to_vec(&layout.geometry).unwrap();
        layout.geometry = serde_json::from_slice(&encoded).unwrap();
        let mut restored = WorkspaceLayout::restore(Some(layout));
        let builder = restored.native_builder(surface.0, "Terminal".into());
        assert_eq!(builder.position, Some(rect.min));
        assert_eq!(builder.inner_size, Some(rect.size()));
    }

    fn leaf_tabs(layout: &WorkspaceLayout, node: NodeIndex) -> Vec<Panel> {
        layout.dock.main_surface()[node]
            .tabs()
            .map(<[Panel]>::to_vec)
            .unwrap_or_default()
    }

    #[test]
    fn default_layout_opens_summary_immediately_before_run_history() {
        let layout = WorkspaceLayout::default();
        let top = NodeIndex::root().left();
        assert_eq!(
            leaf_tabs(&layout, top),
            [
                Panel::Summary,
                Panel::RunHistory,
                Panel::Trace,
                Panel::Network,
                Panel::Memory,
                Panel::CoreDump,
                Panel::Triage,
                Panel::StaticAnalysis
            ]
        );
        let egui_dock::Node::Leaf { tabs, active, .. } = &layout.dock.main_surface()[top] else {
            panic!("top node must hold tabs");
        };
        assert_eq!(tabs[active.0], Panel::Summary);
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
            [
                Panel::Summary,
                Panel::RunHistory,
                Panel::Trace,
                Panel::Network,
                Panel::Memory,
                Panel::CoreDump,
                Panel::Triage,
                Panel::StaticAnalysis
            ]
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
    fn version_three_migration_preserves_detached_history_and_custom_geometry() {
        let mut layout = WorkspaceLayout {
            version: 3,
            ..WorkspaceLayout::default()
        };
        layout
            .dock
            .remove_tab(layout.dock.find_tab(&Panel::Summary).unwrap());
        layout
            .dock
            .remove_tab(layout.dock.find_tab(&Panel::RunHistory).unwrap());
        let surface = layout
            .dock
            .add_window(vec![Panel::Activity, Panel::RunHistory]);
        let rect = Rect::from_min_size(egui::pos2(160.0, 140.0), egui::vec2(800.0, 550.0));
        layout.geometry.insert(surface.0, rect);
        let restored = WorkspaceLayout::restore(Some(layout));
        let (summary_surface, node, tab) = restored.dock.find_tab(&Panel::Summary).unwrap();
        assert_eq!(summary_surface, surface);
        assert_eq!(restored.geometry[&surface.0], rect);
        let egui_dock::Node::Leaf { tabs, active, .. } = &restored.dock[surface][node] else {
            panic!("history window must remain a leaf");
        };
        assert_eq!(tabs, &[Panel::Activity, Panel::Summary, Panel::RunHistory]);
        assert_eq!(*active, tab);
        assert_eq!(restored.version, LAYOUT_VERSION);
        let restored = WorkspaceLayout::restore(Some(restored));
        assert_eq!(
            restored
                .dock
                .iter_all_tabs()
                .filter(|(_, panel)| **panel == Panel::Summary)
                .count(),
            1
        );
    }

    #[test]
    fn missing_summary_and_history_return_beside_each_other() {
        for missing in [Panel::Summary, Panel::RunHistory] {
            let mut layout = WorkspaceLayout::default();
            layout
                .dock
                .remove_tab(layout.dock.find_tab(&missing).unwrap());
            layout.validate();
            let (surface, node, summary) = layout.dock.find_tab(&Panel::Summary).unwrap();
            let (history_surface, history_node, history) =
                layout.dock.find_tab(&Panel::RunHistory).unwrap();
            assert_eq!((surface, node), (history_surface, history_node));
            assert_eq!(summary.0 + 1, history.0);
        }
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
            [
                Panel::Summary,
                Panel::RunHistory,
                Panel::Trace,
                Panel::Network,
                Panel::Memory,
                Panel::CoreDump,
                Panel::Triage,
                Panel::StaticAnalysis
            ]
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
            [
                Panel::Summary,
                Panel::RunHistory,
                Panel::Trace,
                Panel::Network,
                Panel::Memory,
                Panel::CoreDump,
                Panel::Triage,
                Panel::StaticAnalysis
            ]
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
            [
                Panel::Summary,
                Panel::RunHistory,
                Panel::Trace,
                Panel::Network,
                Panel::Memory,
                Panel::CoreDump,
                Panel::Triage,
                Panel::StaticAnalysis
            ]
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
    fn detached_analysis_panels_do_not_expand_the_floating_window_every_frame() {
        for panel in [
            Panel::Network,
            Panel::Memory,
            Panel::CoreDump,
            Panel::StaticAnalysis,
            Panel::Summary,
        ] {
            for (size, font_size) in [
                (egui::vec2(1280.0, 900.0), 16.0),
                (egui::vec2(800.0, 600.0), 24.0),
            ] {
                let mut app = crate::app::tests::upload_app();
                let mut layout = WorkspaceLayout::default();
                let location = layout.dock.find_tab(&panel).unwrap();
                let surface = layout.dock.detach_tab(
                    location,
                    Rect::from_min_size(egui::pos2(50.0, 50.0), egui::vec2(500.0, 400.0)),
                );
                let id = egui::Id::new(("workspace-fallback", surface.0));
                let ctx = egui::Context::default();
                theme::install(&ctx);
                theme::text_size(&ctx, font_size);
                ctx.set_embed_viewports(true);
                let mut settled = None;
                for frame in 0..90 {
                    let _ = ctx.run(
                        egui::RawInput {
                            screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, size)),
                            time: Some(frame as f64 / 60.0),
                            ..Default::default()
                        },
                        |ctx| layout.show(&mut app, ctx),
                    );
                    let rect = ctx
                        .memory(|memory| memory.area_rect(id))
                        .expect("detached panel");
                    if frame == 2 {
                        settled = Some(rect.size());
                    }
                    if frame > 2 {
                        let first = settled.unwrap();
                        assert!((rect.width()-first.x).abs() <= 1.0 && (rect.height()-first.y).abs() <= 1.0,
                            "{panel:?} grows at {size:?}/{font_size}, frame {frame}: {first:?} -> {:?}", rect.size());
                    }
                }
            }
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
        assert_eq!(layout.dock.iter_all_tabs().count(), 10);
        assert_eq!(
            layout
                .dock
                .iter_all_tabs()
                .filter(|(_, tab)| **tab == Panel::Trace)
                .count(),
            1
        );
        assert!((1..layout.dock.surfaces_count())
            .all(|index| !layout.dock.is_surface_valid(SurfaceIndex(index))
                || layout.dock[SurfaceIndex(index)].tabs().next().is_some()));
    }

    #[test]
    fn restored_empty_windows_preserve_later_surface_geometry_and_live_panels() {
        let mut layout = WorkspaceLayout::default();
        let stale = layout
            .dock
            .add_window(vec![Panel::Terminal("ended".into())]);
        let trace = layout.dock.find_tab(&Panel::Trace).unwrap();
        let rectangle = Rect::from_min_size(egui::pos2(560.0, 240.0), egui::vec2(700.0, 400.0));
        let retained = layout.dock.detach_tab(trace, rectangle);
        layout.geometry.insert(
            stale.0,
            Rect::from_min_size(egui::pos2(30.0, 40.0), egui::vec2(600.0, 300.0)),
        );
        layout.geometry.insert(retained.0, rectangle);
        let mut restored = WorkspaceLayout::restore(Some(layout));
        restored.validate();
        assert!(!restored.dock.is_surface_valid(stale));
        assert!(!restored.geometry.contains_key(&stale.0));
        assert_eq!(restored.dock.find_tab(&Panel::Trace).unwrap().0, retained);
        assert_eq!(restored.geometry.get(&retained.0), Some(&rectangle));
        assert_eq!(restored.dock.iter_all_tabs().count(), 10);

        let ended = restored
            .dock
            .add_window(vec![Panel::Terminal("later".into())]);
        let location = restored
            .dock
            .find_tab(&Panel::Terminal("later".into()))
            .unwrap();
        restored.dock.remove_tab(location);
        restored.remove_empty_windows();
        assert!(!restored.dock.is_surface_valid(ended));
        assert_eq!(restored.dock.find_tab(&Panel::Trace).unwrap().0, retained);
        assert_eq!(restored.geometry.get(&retained.0), Some(&rectangle));
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
