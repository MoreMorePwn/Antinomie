// SPDX-License-Identifier: GPL-3.0-only
//! Branching VM checkpoint presentation. Core owns storage and VM operations.

use crate::theme;
use antinomie_monitor_core::{
    Command, SnapshotProfile, SnapshotRequest, VmCheckpoint, VmSnapshotConsistency, VmSnapshotMode,
    VmSnapshotProgress, VmSnapshotTree,
};
use eframe::egui::{self, RichText};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const WINDOW_ID: &str = "vm_snapshots";
const NODE_WIDTH: f32 = 210.0;
const NODE_HEIGHT: f32 = 84.0;
const COLUMN_STEP: f32 = 252.0;
const ROW_STEP: f32 = 108.0;

#[derive(Clone)]
struct Draft {
    name: String,
    description: String,
    mode: VmSnapshotMode,
}

impl Default for Draft {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            mode: VmSnapshotMode::Disk,
        }
    }
}

impl Draft {
    fn request(&self) -> SnapshotRequest {
        SnapshotRequest {
            name: self.name.trim().to_owned(),
            description: self.description.clone(),
            mode: self.mode,
        }
    }
}

enum Decision {
    Create(Draft),
    Restore {
        id: String,
        boot_from_disk: bool,
        save: bool,
        draft: Draft,
    },
    Rename {
        id: String,
        name: String,
    },
    Delete {
        id: String,
    },
}

/// UI-only state. An open manager stays bound to its VM when sidebar selection changes.
pub(crate) struct SnapshotManager {
    pub(crate) open: bool,
    pub(crate) vm_id: Option<String>,
    vm_name: String,
    pub(crate) selected: Option<String>,
    tree_view: bool,
    zoom: f32,
    pan: egui::Vec2,
    fit: bool,
    decision: Option<Decision>,
    pub(crate) pending: Option<u64>,
    pub(crate) result: Option<(bool, String)>,
    /// Centre the window the next time it is drawn: as it opens, wherever
    /// it was last (a saved position can be off the screen).
    place: bool,
}

impl Default for SnapshotManager {
    fn default() -> Self {
        Self {
            open: false,
            vm_id: None,
            vm_name: String::new(),
            selected: None,
            tree_view: false,
            zoom: 1.0,
            pan: egui::Vec2::ZERO,
            fit: true,
            decision: None,
            pending: None,
            result: None,
            place: true,
        }
    }
}

impl SnapshotManager {
    pub(crate) fn bind(&mut self, vm_id: &str, vm_name: &str) {
        if self.vm_id.as_deref() != Some(vm_id) {
            *self = Self::default();
            self.vm_id = Some(vm_id.to_owned());
        }
        self.vm_name = vm_name.to_owned();
        if !self.open {
            self.place = true;
        }
        self.open = true;
    }

    pub(crate) fn close(&mut self) {
        if self.decision.is_some() {
            self.decision = None;
        } else {
            self.open = false;
        }
    }

    /// The New snapshot decision, as its button opens it.
    #[cfg(test)]
    pub(crate) fn ask_create(&mut self) {
        self.decision = Some(Decision::Create(Draft::default()));
    }

    pub(crate) fn decision_open(&self) -> bool {
        self.open && self.decision.is_some()
    }

    pub(crate) fn complete(&mut self, id: u64, success: bool, message: &str) {
        if self.pending == Some(id) {
            self.pending = None;
            self.result = Some((success, message.to_owned()));
        }
    }

    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        tree: Option<&VmSnapshotTree>,
        progress: Option<&VmSnapshotProgress>,
        enabled: bool,
    ) -> Option<Command> {
        if !self.open {
            return None;
        }
        let mut open = true;
        let mut command = None;
        let mut close = false;
        let busy = self.pending.is_some() || progress.is_some();
        let enabled = enabled && !busy;
        let window = crate::widgets::window(format!("Snapshots · {}", self.vm_name))
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut open)
            .collapsible(false)
            .default_size([1060.0, 660.0])
            .min_size([320.0, 260.0])
            // A margin all round: the window never touches the app's edges.
            .max_size(
                (ctx.screen_rect().size() - egui::vec2(96.0, 140.0)).max(egui::vec2(320.0, 260.0)),
            )
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center());
        let window = if std::mem::take(&mut self.place) {
            window.current_pos(ctx.screen_rect().center())
        } else {
            window
        };
        window.show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        enabled
                            && tree.is_some_and(|t| {
                                t.capabilities.can_create_disk || t.capabilities.can_create_full
                            }),
                        primary("New snapshot…"),
                    )
                    .clicked()
                {
                    let mode = if tree.is_some_and(|t| t.capabilities.can_create_disk) {
                        VmSnapshotMode::Disk
                    } else {
                        VmSnapshotMode::Full
                    };
                    self.decision = Some(Decision::Create(Draft {
                        mode,
                        ..Draft::default()
                    }));
                }
                if ui
                    .add_enabled(enabled, egui::Button::new("Refresh"))
                    .clicked()
                {
                    command = self
                        .vm_id
                        .as_ref()
                        .map(|id| Command::RefreshVmSnapshots { vm_id: id.clone() });
                }
                let mut graph = !self.tree_view;
                if crate::widgets::segmented(
                    ui,
                    [
                        (true, crate::widgets::TabItem::new("Graph")),
                        (false, crate::widgets::TabItem::new("Tree")),
                    ],
                    &mut graph,
                ) {
                    self.tree_view = !graph;
                }
                if !self.tree_view {
                    if ui.button("Fit").clicked() {
                        self.fit = true;
                    }
                    if ui.button("−").on_hover_text("Zoom out").clicked() {
                        self.zoom = (self.zoom / 1.2).max(0.001);
                    }
                    if ui.button("+").on_hover_text("Zoom in").clicked() {
                        self.zoom = (self.zoom * 1.2).min(2.0);
                    }
                    ui.label(
                        RichText::new(format!("{:.1}%", self.zoom * 100.0)).color(theme::muted()),
                    );
                }
            });
            ui.add_space(4.0);
            if let Some(progress) = progress {
                ui.horizontal_wrapped(|ui| {
                    crate::theme::spinner(ui);
                    ui.label(&progress.stage);
                });
            } else if self.pending.is_some() {
                ui.horizontal(|ui| {
                    crate::theme::spinner(ui);
                    ui.label("Waiting for snapshot operation…");
                });
            }
            if let Some((success, message)) = &self.result {
                if !*success {
                    crate::activity::error_toast(ui, message);
                } else {
                    ui.colored_label(theme::good(), message);
                };
            }
            let Some(tree) = tree else {
                crate::theme::loading(ui, "Loading snapshots…");
                // The graph's room: the window keeps its size (and its
                // close button its place) when the list arrives.
                let cap = (ui.ctx().screen_rect().height() * 0.6).max(140.0);
                ui.allocate_space(egui::vec2(ui.available_width(), cap));
                close |= footer(ui);
                return;
            };
            if let Some(note) = &tree.recovery_note {
                crate::activity::warning(ui, note);
            }
            if let Some(reason) = &tree.capabilities.reason {
                ui.weak(reason);
            }
            if self
                .selected
                .as_ref()
                .is_some_and(|id| !tree.nodes.iter().any(|node| &node.id == id))
            {
                self.selected = None;
            }
            let width = ui.available_width();
            // Leave the hint line below the view its full height, or the
            // window grows a little every frame.
            let footer_height =
                ui.spacing().interact_size.y + 2.0 * ui.spacing().item_spacing.y + 18.0;
            // Capped, so the window settles with a margin to the app's edges.
            let cap = (ui.ctx().screen_rect().height() * 0.6).max(140.0);
            let height = (ui.available_height() - footer_height).clamp(140.0, cap);
            if width >= 740.0 {
                // The two parts and the gap between them add up to the
                // width exactly, or the window widens every frame.
                let gap = ui.spacing().item_spacing.x;
                let details = 320.0;
                let graph = (width - details - gap).max(200.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(graph, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| self.view(ui, tree, height),
                    );
                    ui.allocate_ui_with_layout(
                        egui::vec2(details, height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            card(ui, details, height, |ui| self.details(ui, tree, enabled));
                        },
                    );
                });
            } else {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.view(ui, tree, (height * 0.6).clamp(160.0, 340.0));
                    ui.add_space(6.0);
                    card(ui, ui.available_width(), 0.0, |ui| {
                        self.details(ui, tree, enabled)
                    });
                });
            }
            close |= footer(ui);
        });
        let open = open && !close;
        self.open = open;
        if !open {
            self.decision = None;
        }
        if open {
            if let Some(tree) = tree {
                if let Some(decision_command) = self.dialog(ctx, tree, enabled) {
                    command = Some(decision_command);
                }
            }
        }
        command
    }

    fn view(&mut self, ui: &mut egui::Ui, tree: &VmSnapshotTree, height: f32) {
        if self.tree_view {
            self.tree(ui, tree, height);
        } else {
            self.graph(ui, tree, height);
        }
    }

    fn tree(&mut self, ui: &mut egui::Ui, tree: &VmSnapshotTree, height: f32) {
        egui::ScrollArea::both()
            .max_height(height)
            .id_salt("snapshot_tree")
            .show(ui, |ui| {
                ui.label(RichText::new("Base image").strong().color(theme::text()));
                let items = graph_layout(tree);
                // The base image is the root; every checkpoint hangs below it.
                let depths: Vec<_> = items.iter().map(|item| item.depth + 1).collect();
                let mono = egui::TextStyle::Monospace.resolve(ui.style());
                let char_width = crate::tree_lines::char_width(ui, &mono);
                for (item, branch) in items.iter().zip(crate::tree_lines::prefixes(&depths)) {
                    let node = &tree.nodes[item.index];
                    crate::tree_lines::row(ui, &branch, char_width, |ui| {
                        let name = if node.deleted {
                            "Hidden checkpoint"
                        } else {
                            &node.name
                        };
                        let response = ui.selectable_label(
                            self.selected.as_deref() == Some(&node.id),
                            format!("{name}  ({})", mode_label(node.mode)),
                        );
                        if response.clicked() {
                            response.request_focus();
                            self.selected = Some(node.id.clone());
                        }
                        if tree.active_parent_id.as_deref() == Some(&node.id) {
                            ui.colored_label(theme::good(), "Current parent");
                        }
                    });
                }
                ui.colored_label(theme::good(), "● You are here — Unsaved changes")
                    .on_hover_text("Use Tab and Enter to select checkpoints and actions.");
            });
    }

    fn graph(&mut self, ui: &mut egui::Ui, tree: &VmSnapshotTree, height: f32) {
        let size = egui::vec2(ui.available_width().max(100.0), height);
        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click_and_drag());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 6.0, theme::bg());
        painter.rect_stroke(
            rect,
            6.0,
            egui::Stroke::new(1.0_f32, theme::line_soft()),
            egui::StrokeKind::Inside,
        );
        let items = graph_layout(tree);
        let points: BTreeMap<&str, egui::Pos2> = items
            .iter()
            .map(|item| {
                (
                    tree.nodes[item.index].id.as_str(),
                    egui::pos2(
                        (item.depth + 1) as f32 * COLUMN_STEP,
                        item.row as f32 * ROW_STEP,
                    ),
                )
            })
            .collect();
        let current_parent = tree
            .active_parent_id
            .as_deref()
            .and_then(|id| points.get(id))
            .copied()
            .unwrap_or(egui::Pos2::ZERO);
        let current_row = items
            .iter()
            .map(|item| item.row)
            .max()
            .map_or(0, |row| row + 1);
        let current = egui::pos2(
            current_parent.x + COLUMN_STEP,
            current_row as f32 * ROW_STEP,
        );
        if self.fit {
            let max_x = points.values().map(|p| p.x).fold(current.x, f32::max) + NODE_WIDTH;
            let max_y = points.values().map(|p| p.y).fold(current.y, f32::max) + NODE_HEIGHT;
            self.zoom = ((rect.width() - 32.0) / max_x.max(1.0))
                .min((rect.height() - 32.0) / max_y.max(1.0))
                .clamp(0.001, 1.2);
            self.pan = egui::vec2(16.0, 16.0);
            self.fit = false;
        }
        if response.dragged() {
            self.pan += response.drag_delta();
        }
        if response.hovered() {
            let scroll = ui.input(|input| input.smooth_scroll_delta);
            if ui.input(|input| input.modifiers.ctrl || input.modifiers.command) {
                self.zoom = (self.zoom * (scroll.y * 0.002).exp()).clamp(0.001, 2.0);
            } else {
                self.pan += scroll;
            }
        }
        let transform = |point: egui::Pos2| rect.min + self.pan + point.to_vec2() * self.zoom;
        let node_size = egui::vec2(NODE_WIDTH, NODE_HEIGHT) * self.zoom;
        let font_size = ui.style().text_styles[&egui::TextStyle::Body].size * self.zoom;
        let edge = |parent: egui::Pos2, child: egui::Pos2, color| {
            let start = transform(parent) + egui::vec2(node_size.x, node_size.y * 0.5);
            let end = transform(child) + egui::vec2(0.0, node_size.y * 0.5);
            let x = (start.x + end.x) * 0.5;
            painter.add(egui::Shape::line(
                vec![start, egui::pos2(x, start.y), egui::pos2(x, end.y), end],
                egui::Stroke::new(1.5_f32, color),
            ));
        };
        for item in &items {
            let node = &tree.nodes[item.index];
            let point = points[&node.id.as_str()];
            let parent = node
                .parent_id
                .as_deref()
                .and_then(|id| points.get(id))
                .copied()
                .unwrap_or(egui::Pos2::ZERO);
            edge(parent, point, theme::line());
        }
        edge(current_parent, current, theme::good());
        paint_node(
            &painter,
            egui::Rect::from_min_size(transform(egui::Pos2::ZERO), node_size),
            "Base image",
            "Initial disk",
            theme::line(),
            false,
            font_size,
        );
        for item in &items {
            let node = &tree.nodes[item.index];
            let node_rect =
                egui::Rect::from_min_size(transform(points[&node.id.as_str()]), node_size);
            let selected = self.selected.as_deref() == Some(&node.id);
            let color = if selected {
                theme::blue()
            } else if !node.compatible {
                theme::warn()
            } else {
                theme::line()
            };
            paint_node(
                &painter,
                node_rect,
                if node.deleted {
                    "Hidden checkpoint"
                } else {
                    &node.name
                },
                mode_label(node.mode),
                color,
                selected,
                font_size,
            );
            if node_rect.intersects(rect) {
                let hit = ui.interact(
                    node_rect.intersect(rect),
                    response.id.with(&node.id),
                    egui::Sense::click(),
                );
                if hit.clicked() {
                    self.selected = Some(node.id.clone());
                }
                hit.on_hover_text(format!("{}\n{}", node.name, node.description));
            }
        }
        paint_node(
            &painter,
            egui::Rect::from_min_size(transform(current), node_size),
            "You are here",
            "Unsaved changes",
            theme::good(),
            false,
            font_size,
        );
        response.on_hover_text(
            "Drag to pan. Scroll to pan; Ctrl + scroll to zoom. Use Tree for keyboard navigation.",
        );
    }

    fn details(&mut self, ui: &mut egui::Ui, tree: &VmSnapshotTree, enabled: bool) {
        let Some(node) = self
            .selected
            .as_ref()
            .and_then(|id| tree.nodes.iter().find(|node| &node.id == id))
        else {
            ui.label(
                RichText::new("Snapshot details")
                    .strong()
                    .color(theme::text()),
            );
            ui.add(
                egui::Label::new(if tree.nodes.is_empty() {
                    "Save a snapshot to keep this VM state."
                } else {
                    "Select a checkpoint in the graph or tree."
                })
                .wrap(),
            );
            return;
        };
        ui.add(egui::Label::new(RichText::new(&node.name).strong().color(theme::text())).wrap());
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Selected checkpoint")
                    .small()
                    .color(theme::muted()),
            );
            crate::widgets::chip(
                ui,
                mode_label(node.mode),
                if node.mode == VmSnapshotMode::Full {
                    crate::widgets::Tone::Info
                } else {
                    crate::widgets::Tone::Neutral
                },
            );
        });
        if node.deleted {
            ui.colored_label(theme::muted(), "Hidden")
                .on_hover_text("Retained for branch dependencies");
        }
        if !node.description.is_empty() {
            ui.add(egui::Label::new(RichText::new(&node.description).color(theme::muted())).wrap());
        }
        ui.add_space(4.0);
        egui::Grid::new("snapshot_details")
            .num_columns(2)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for (label, value) in [
                    ("Created", created_time(node.created_unix_ms)),
                    (
                        "Consistency",
                        consistency_label(node.consistency).to_owned(),
                    ),
                    ("Disk layer", crate::values::file_size(node.disk_size)),
                    ("Memory state", crate::values::file_size(node.memory_size)),
                    (
                        "Configuration",
                        format!("{} CPUs, {} MiB RAM", node.config.cpus, node.config.ram_mib),
                    ),
                    (
                        "Stealth profile",
                        match &node.profile {
                            SnapshotProfile::Same => "The VM's current profile".to_owned(),
                            SnapshotProfile::Other { machine } => format!("{machine} (differs)"),
                            SnapshotProfile::Unknown => "Not recorded".to_owned(),
                        },
                    ),
                ] {
                    ui.label(RichText::new(label).color(theme::muted()));
                    ui.add(egui::Label::new(RichText::new(value).color(theme::text())).wrap());
                    ui.end_row();
                }
            });
        if let Some(note) = &node.compatibility_note {
            crate::activity::warning(ui, note);
        }
        ui.add_space(6.0);
        let restore = enabled && tree.capabilities.can_restore && !node.deleted;
        if node.mode == VmSnapshotMode::Full
            && ui
                .add_enabled(
                    restore && node.compatible,
                    egui::Button::new("Resume disk + memory…"),
                )
                .clicked()
        {
            self.restore_dialog(node, false);
        }
        if ui
            .add_enabled(restore, egui::Button::new("Restore disk and boot…"))
            .clicked()
        {
            self.restore_dialog(node, true);
        }
        if ui
            .add_enabled(enabled && !node.deleted, egui::Button::new("Rename…"))
            .clicked()
        {
            self.decision = Some(Decision::Rename {
                id: node.id.clone(),
                name: node.name.clone(),
            });
        }
        let referenced = is_referenced(tree, &node.id);
        if ui
            .add_enabled(
                enabled && !node.deleted,
                egui::Button::new(
                    RichText::new(if referenced {
                        "Hide checkpoint…"
                    } else {
                        "Delete checkpoint…"
                    })
                    .color(theme::error()),
                ),
            )
            .clicked()
        {
            self.decision = Some(Decision::Delete {
                id: node.id.clone(),
            });
        }
    }

    fn restore_dialog(&mut self, node: &VmCheckpoint, boot_from_disk: bool) {
        self.decision = Some(Decision::Restore {
            id: node.id.clone(),
            boot_from_disk,
            save: true,
            draft: Draft {
                name: "Before restore".into(),
                ..Draft::default()
            },
        });
    }

    fn dialog(
        &mut self,
        ctx: &egui::Context,
        tree: &VmSnapshotTree,
        enabled: bool,
    ) -> Option<Command> {
        let decision = self.decision.as_mut()?;
        let mut command = None;
        let mut cancel = false;
        let vm_id = tree.vm_id.clone();
        let title = match decision {
            Decision::Create(_) => "New snapshot",
            Decision::Restore { .. } => "Restore snapshot",
            Decision::Rename { .. } => "Rename snapshot",
            Decision::Delete { .. } => "Delete snapshot",
        };
        let mut open = true;
        // Like the other spawned windows: no dim behind it and free to move.
        crate::widgets::window(title)
            .id(egui::Id::new("snapshot_decision"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .show(ctx, |ui| {
                ui.set_width((ctx.screen_rect().width() - 48.0).clamp(240.0, 440.0));
                egui::ScrollArea::vertical().max_height((ctx.screen_rect().height() - 180.0).max(100.0)).show(ui, |ui| {
                    match decision {
                        Decision::Create(draft) => {
                            draft_form(ui, draft, tree);
                        }
                        Decision::Restore { id, boot_from_disk, save, draft } => {
                            let node = tree.nodes.iter().find(|node| &node.id == id);
                            ui.label(format!("Restore {}?", node.map(|node| node.name.as_str()).unwrap_or("checkpoint")));
                            ui.label(if *boot_from_disk { "The VM will boot with the saved disk. Running programs are lost." } else { "The VM will resume saved disk, RAM and programs." });
                            ui.weak("Existing branches and recordings remain saved. A new observation timeline starts.");
                            match node.map(|node| &node.profile) {
                                Some(SnapshotProfile::Other { machine }) => {
                                    crate::activity::warning(ui, format!("This snapshot was taken as {machine}. The VM's stealth profile is different, so restoring switches the VM back to that profile."));
                                }
                                Some(SnapshotProfile::Unknown) => {
                                    ui.weak("This snapshot has no recorded stealth profile (taken before profiles were recorded), so it restores as it is.");
                                }
                                _ => {}
                            }
                            ui.separator();
                            ui.radio_value(save, true, "Save current state first");
                            ui.radio_value(save, false, "Discard current unsaved state");
                            if *save { draft_form(ui, draft, tree); }
                        }
                        Decision::Rename { name, .. } => {
                            ui.label("Name"); ui.add(egui::TextEdit::singleline(name).desired_width(ui.available_width()).char_limit(128));
                        }
                        Decision::Delete { id } => {
                            let referenced = is_referenced(tree, id);
                            ui.label(if referenced { "Hide this checkpoint? Its disk remains available to dependent branches." } else { "Delete this checkpoint? This removes its restore point." });
                            ui.weak("Other branches and recordings are preserved.");
                        }
                    }
                });
                let (label, ready) = match &*decision {
                    Decision::Create(draft) => ("Save snapshot", enabled && valid_draft(draft, tree)),
                    Decision::Restore { id, boot_from_disk, save, draft } => {
                        let node = tree.nodes.iter().find(|node| &node.id == id);
                        let switch = node.is_some_and(|node| matches!(node.profile, SnapshotProfile::Other { .. }));
                        (match (switch, *save) { (true, true) => "Save current, switch profile and restore", (true, false) => "Switch profile and restore", (false, true) => "Save current and restore", (false, false) => "Discard changes and restore" }, enabled && tree.capabilities.can_restore && node.is_some_and(|node| !node.deleted && (*boot_from_disk || node.compatible)) && (!*save || valid_draft(draft, tree)))
                    }
                    Decision::Rename { id, name } => ("Rename", enabled && !name.trim().is_empty() && tree.nodes.iter().any(|node| &node.id == id && !node.deleted)),
                    Decision::Delete { id } => (if is_referenced(tree, id) { "Hide checkpoint" } else { "Delete checkpoint" }, enabled && tree.nodes.iter().any(|node| &node.id == id && !node.deleted)),
                };
                crate::widgets::footer_split(ui, |_| {}, |ui| {
                    if ui.add_enabled(ready, primary(label)).clicked() {
                        command = Some(match &*decision {
                            Decision::Create(draft) => Command::CreateVmSnapshot { vm_id: vm_id.clone(), request: draft.request() },
                            Decision::Restore { id, boot_from_disk, save, draft } => Command::RestoreVmSnapshot { vm_id: vm_id.clone(), snapshot_id: id.clone(), boot_from_disk: *boot_from_disk, save_current: save.then(|| draft.request()), confirmed: true, switch_profile: tree.nodes.iter().any(|node| &node.id == id && matches!(node.profile, SnapshotProfile::Other { .. })) },
                            Decision::Rename { id, name } => Command::RenameVmSnapshot { vm_id: vm_id.clone(), snapshot_id: id.clone(), name: name.trim().to_owned() },
                            Decision::Delete { id } => Command::DeleteVmSnapshot { vm_id: vm_id.clone(), snapshot_id: id.clone(), confirmed: true },
                        });
                    }
                    cancel = ui.button("Cancel").clicked();
                });
            });
        if !open || cancel || command.is_some() {
            self.decision = None;
        }
        command
    }
}

/// The main action of the window, in the primary color.
fn primary(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(theme::palette().primary_text))
        .fill(theme::primary())
}

/// The window's footer: the branch hint at the left, Close at the right.
/// Returns whether Close was pressed.
fn footer(ui: &mut egui::Ui) -> bool {
    let mut close = false;
    crate::widgets::footer_split(
        ui,
        |_| {},
        |ui| {
            close = ui
                .button("Close")
                .on_hover_text("Restore a checkpoint, then save another to create a branch.")
                .clicked()
        },
    );
    close
}

/// The selected checkpoint's panel: a bordered card of `width`, scrolling
/// inside `height` (0: as tall as its content).
fn card(ui: &mut egui::Ui, width: f32, height: f32, content: impl FnOnce(&mut egui::Ui)) {
    let margin = 10.0;
    egui::Frame::new()
        .fill(theme::raised())
        .stroke(egui::Stroke::new(1.0_f32, theme::line_soft()))
        .corner_radius(6)
        .inner_margin(margin)
        .show(ui, |ui| {
            ui.set_width((width - 2.0 * margin - 2.0).max(100.0));
            if height > 0.0 {
                let inner = (height - 2.0 * margin - 2.0).max(60.0);
                ui.set_min_height(inner);
                egui::ScrollArea::vertical()
                    .max_height(inner)
                    .auto_shrink([false, false])
                    .show(ui, content);
            } else {
                content(ui);
            }
        });
}

fn draft_form(ui: &mut egui::Ui, draft: &mut Draft, tree: &VmSnapshotTree) {
    ui.label("Name");
    ui.add(
        egui::TextEdit::singleline(&mut draft.name)
            .desired_width(ui.available_width())
            .char_limit(128),
    );
    ui.label("Description");
    ui.add(
        egui::TextEdit::multiline(&mut draft.description)
            .desired_width(ui.available_width())
            .desired_rows(2)
            .char_limit(4096),
    );
    ui.add_enabled_ui(tree.capabilities.can_create_disk, |ui| {
        ui.radio_value(&mut draft.mode, VmSnapshotMode::Disk, "Disk only")
            .on_hover_text("Restores files and boots afresh. Live snapshots are crash-consistent.");
    });
    ui.add_enabled_ui(tree.capabilities.can_create_full, |ui| {
        ui.radio_value(&mut draft.mode, VmSnapshotMode::Full, "Disk + memory")
            .on_hover_text(
                "Preserves RAM and running programs. Uses more storage and requires compatible guest recovery.",
            );
    });
}

fn valid_draft(draft: &Draft, tree: &VmSnapshotTree) -> bool {
    !draft.name.trim().is_empty()
        && match draft.mode {
            VmSnapshotMode::Disk => tree.capabilities.can_create_disk,
            VmSnapshotMode::Full => tree.capabilities.can_create_full,
        }
}

fn is_referenced(tree: &VmSnapshotTree, id: &str) -> bool {
    tree.active_parent_id.as_deref() == Some(id)
        || tree
            .nodes
            .iter()
            .any(|node| node.parent_id.as_deref() == Some(id))
}

struct PlacedNode {
    index: usize,
    depth: usize,
    row: usize,
}

/// Iterative parent-first layout retains hidden dependency nodes and tolerates malformed cycles.
fn graph_layout(tree: &VmSnapshotTree) -> Vec<PlacedNode> {
    let mut children: BTreeMap<Option<&str>, Vec<usize>> = BTreeMap::new();
    let ids: BTreeSet<&str> = tree.nodes.iter().map(|node| node.id.as_str()).collect();
    for (index, node) in tree.nodes.iter().enumerate() {
        let parent = node
            .parent_id
            .as_deref()
            .filter(|id| ids.contains(id) && *id != node.id);
        children.entry(parent).or_default().push(index);
    }
    let mut stack: Vec<(usize, usize)> = children
        .get(&None)
        .into_iter()
        .flatten()
        .rev()
        .map(|index| (*index, 0))
        .collect();
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(tree.nodes.len());
    let mut row = 0;
    loop {
        if stack.is_empty() {
            let Some(index) = (0..tree.nodes.len()).find(|index| !seen.contains(index)) else {
                break;
            };
            stack.push((index, 0));
        }
        while let Some((index, depth)) = stack.pop() {
            if !seen.insert(index) {
                continue;
            }
            output.push(PlacedNode { index, depth, row });
            if let Some(next) = children
                .get(&Some(tree.nodes[index].id.as_str()))
                .filter(|next| next.iter().any(|index| !seen.contains(index)))
            {
                stack.extend(
                    next.iter()
                        .rev()
                        .map(|index| (*index, depth.saturating_add(1))),
                );
            } else {
                row += 1;
            }
        }
    }
    output
}

fn paint_node(
    painter: &egui::Painter,
    rect: egui::Rect,
    name: &str,
    detail: &str,
    color: egui::Color32,
    selected: bool,
    font_size: f32,
) {
    painter.rect_filled(
        rect,
        4.0,
        if selected {
            theme::palette().selection
        } else {
            theme::raised()
        },
    );
    painter.rect_stroke(
        rect,
        4.0,
        egui::Stroke::new(if selected { 2.0_f32 } else { 1.0_f32 }, color),
        egui::StrokeKind::Inside,
    );
    if rect.height() < 20.0 {
        painter.circle_filled(rect.center(), 2.0, color);
        return;
    }
    let font = egui::FontId::proportional(font_size.clamp(12.0, 24.0));
    // Room between the text and the node's border, growing with the zoom.
    let pad = (rect.height() * 0.1).clamp(4.0, 12.0);
    let mut job = egui::text::LayoutJob::simple(
        name.to_owned(),
        font,
        theme::text(),
        (rect.width() - 2.0 * pad).max(1.0),
    );
    job.wrap.max_rows = 1;
    let galley = painter.layout_job(job);
    let clip = painter.with_clip_rect(painter.clip_rect().intersect(rect.shrink(pad / 2.0)));
    clip.galley(rect.min + egui::vec2(pad, pad), galley, theme::text());
    if rect.height() >= 32.0 {
        clip.text(
            rect.left_bottom() + egui::vec2(pad, -pad),
            egui::Align2::LEFT_BOTTOM,
            detail,
            egui::FontId::proportional((font_size * 0.81).clamp(12.0, 24.0)),
            if color == theme::line() {
                theme::muted()
            } else {
                color
            },
        );
    }
}

fn mode_label(mode: VmSnapshotMode) -> &'static str {
    match mode {
        VmSnapshotMode::Disk => "Disk only",
        VmSnapshotMode::Full => "Disk + memory",
    }
}
fn consistency_label(consistency: VmSnapshotConsistency) -> &'static str {
    match consistency {
        VmSnapshotConsistency::Stopped => "Stopped VM",
        VmSnapshotConsistency::CrashConsistent => "Crash-consistent",
        VmSnapshotConsistency::Paused => "Paused disk + memory",
    }
}

/// Format UTC without a new dependency; 400-year cycles bound the year loop.
fn created_time(unix_ms: u64) -> String {
    let seconds = unix_ms / 1000;
    let mut days = seconds / 86_400;
    let mut year = 1970;
    if days >= 10_957 {
        days -= 10_957;
        year = 2000 + (days / 146_097) * 400;
        days %= 146_097;
    }
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    loop {
        let year_days = if leap(year) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        year += 1;
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for month_days in months {
        if days < month_days {
            break;
        }
        days -= month_days;
        month += 1;
    }
    format!(
        "{year:04}-{month:02}-{:02} {:02}:{:02} UTC",
        days + 1,
        (seconds / 3600) % 24,
        (seconds / 60) % 60
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use antinomie_monitor_core::{VmConfig, VmSnapshotCapabilities};

    pub(crate) fn fixture() -> VmSnapshotTree {
        let checkpoint = |id: &str, parent: Option<&str>, name: &str, mode| VmCheckpoint {
            id: id.into(),
            parent_id: parent.map(str::to_owned),
            name: name.into(),
            description: "A retained VM checkpoint for repeatable experiments.".into(),
            created_unix_ms: 1_800_000_000_000,
            mode,
            consistency: VmSnapshotConsistency::Paused,
            config: VmConfig::default(),
            disk_size: 8 * 1_048_576,
            memory_size: if mode == VmSnapshotMode::Full {
                256 * 1_048_576
            } else {
                0
            },
            compatible: true,
            compatibility_note: None,
            deleted: false,
            stealth: None,
            profile: SnapshotProfile::Same,
        };
        VmSnapshotTree {
            vm_id: "vm".into(),
            nodes: vec![
                checkpoint("desktop", None, "Desktop ready", VmSnapshotMode::Disk),
                checkpoint(
                    "sample",
                    Some("desktop"),
                    "Before sample",
                    VmSnapshotMode::Full,
                ),
                checkpoint("a", Some("sample"), "Experiment A", VmSnapshotMode::Disk),
                checkpoint("b", Some("sample"), "Experiment B", VmSnapshotMode::Full),
            ],
            active_parent_id: Some("b".into()),
            recovery_note: None,
            capabilities: VmSnapshotCapabilities {
                can_create_disk: true,
                can_create_full: true,
                can_restore: true,
                reason: None,
            },
        }
    }

    fn context() -> egui::Context {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        ctx.style_mut(|style| style.animation_time = 0.0);
        ctx
    }

    fn frame(
        ctx: &egui::Context,
        manager: &mut SnapshotManager,
        tree: &VmSnapshotTree,
        events: Vec<egui::Event>,
    ) -> (egui::FullOutput, Option<Command>) {
        let mut command = None;
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 800.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                command = manager.dialog(ctx, tree, true);
            },
        );
        (output, command)
    }

    fn text_rect(output: &egui::FullOutput, label: &str) -> egui::Rect {
        fn find(shape: &egui::Shape, label: &str) -> Option<egui::Rect> {
            match shape {
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, label)),
                egui::Shape::Text(text) if text.galley.text() == label => {
                    Some(text.galley.rect.translate(text.pos.to_vec2()))
                }
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|shape| find(&shape.shape, label))
            .unwrap_or_else(|| {
                let shown: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) => Some(text.galley.text()),
                        _ => None,
                    })
                    .collect();
                panic!("missing UI text: {label}; shown: {shown:?}")
            })
    }

    fn click(
        ctx: &egui::Context,
        manager: &mut SnapshotManager,
        tree: &VmSnapshotTree,
        label: &str,
    ) -> Option<Command> {
        let _ = frame(ctx, manager, tree, Vec::new());
        let (output, command) = frame(ctx, manager, tree, Vec::new());
        assert!(command.is_none());
        let pos = text_rect(&output, label).center();
        frame(
            ctx,
            manager,
            tree,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        frame(
            ctx,
            manager,
            tree,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        )
        .1
    }

    #[test]
    fn restore_confirmation_saves_current_atomically_and_cancel_has_no_command() {
        let ctx = context();
        let tree = fixture();
        let mut manager = SnapshotManager::default();
        manager.bind("vm", "Analyst");
        manager.restore_dialog(&tree.nodes[1], false);
        assert!(frame(&ctx, &mut manager, &tree, Vec::new()).1.is_none());
        let command = click(&ctx, &mut manager, &tree, "Save current and restore").unwrap();
        match command {
            Command::RestoreVmSnapshot {
                vm_id,
                snapshot_id,
                boot_from_disk,
                save_current,
                confirmed,
                switch_profile,
            } => {
                assert_eq!(vm_id, "vm");
                assert_eq!(snapshot_id, "sample");
                assert!(!boot_from_disk && confirmed && !switch_profile);
                assert_eq!(save_current.unwrap().mode, VmSnapshotMode::Disk);
            }
            _ => panic!("expected restore command"),
        }
        assert!(!manager.decision_open());
        manager.restore_dialog(&tree.nodes[1], true);
        assert!(click(&ctx, &mut manager, &tree, "Cancel").is_none());
        assert!(!manager.decision_open());
    }

    #[test]
    fn a_snapshot_of_another_profile_restores_only_by_switching_back() {
        let ctx = context();
        let mut tree = fixture();
        tree.nodes[1].profile = SnapshotProfile::Other {
            machine: "Dell OptiPlex 7090".into(),
        };
        let mut manager = SnapshotManager::default();
        manager.bind("vm", "Analyst");
        manager.restore_dialog(&tree.nodes[1], true);
        frame(&ctx, &mut manager, &tree, Vec::new());
        let (output, _) = frame(&ctx, &mut manager, &tree, Vec::new());
        let text: String = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.text().to_owned()),
                _ => None,
            })
            .collect();
        assert!(text.contains("taken as Dell OptiPlex 7090"), "{text}");
        let command = click(
            &ctx,
            &mut manager,
            &tree,
            "Save current, switch profile and restore",
        )
        .unwrap();
        match command {
            Command::RestoreVmSnapshot { switch_profile, .. } => assert!(switch_profile),
            _ => panic!("expected restore command"),
        }
        // An unknown profile (an old snapshot) restores as it is.
        tree.nodes[1].profile = SnapshotProfile::Unknown;
        manager.restore_dialog(&tree.nodes[1], true);
        let command = click(&ctx, &mut manager, &tree, "Save current and restore").unwrap();
        match command {
            Command::RestoreVmSnapshot { switch_profile, .. } => assert!(!switch_profile),
            _ => panic!("expected restore command"),
        }
    }

    #[test]
    fn discard_restore_and_unsupported_full_mode_use_actual_capabilities() {
        let ctx = context();
        let mut tree = fixture();
        let mut manager = SnapshotManager::default();
        manager.bind("vm", "Analyst");
        manager.restore_dialog(&tree.nodes[1], true);
        assert!(click(&ctx, &mut manager, &tree, "Discard current unsaved state").is_none());
        assert!(matches!(
            click(&ctx, &mut manager, &tree, "Discard changes and restore"),
            Some(Command::RestoreVmSnapshot {
                boot_from_disk: true,
                save_current: None,
                confirmed: true,
                switch_profile: false,
                ..
            })
        ));
        tree.capabilities.can_create_full = false;
        assert!(!valid_draft(
            &Draft {
                name: "Full".into(),
                mode: VmSnapshotMode::Full,
                ..Draft::default()
            },
            &tree
        ));
        assert!(valid_draft(
            &Draft {
                name: "Disk".into(),
                ..Draft::default()
            },
            &tree
        ));
    }

    #[test]
    fn branch_layout_retains_dependencies_and_handles_cycles_without_recursion() {
        let mut tree = fixture();
        tree.nodes[1].deleted = true;
        let layout = graph_layout(&tree);
        assert_eq!(layout.len(), 4);
        assert_eq!(
            layout.iter().map(|item| item.depth).collect::<Vec<_>>(),
            [0, 1, 2, 2]
        );
        assert!(is_referenced(&tree, "sample") && is_referenced(&tree, "b"));
        assert!(!is_referenced(&tree, "a"));
        tree.nodes[0].parent_id = Some("sample".into());
        assert_eq!(graph_layout(&tree).len(), 4);
    }

    #[test]
    fn snapshot_completion_only_matches_its_request_and_switching_vm_resets_selection() {
        let mut manager = SnapshotManager::default();
        manager.bind("vm", "Analyst");
        manager.pending = Some(42);
        manager.selected = Some("sample".into());
        manager.complete(41, true, "other command");
        assert_eq!(manager.pending, Some(42));
        manager.complete(42, false, "disk full");
        assert_eq!(manager.pending, None);
        assert_eq!(manager.result, Some((false, "disk full".into())));
        manager.bind("another", "Other VM");
        assert!(manager.selected.is_none() && manager.result.is_none());
    }

    #[test]
    fn tree_selects_with_keyboard_and_large_font_narrow_manager_remains_scrollable() {
        let ctx = context();
        let tree = fixture();
        let mut manager = SnapshotManager::default();
        manager.bind("vm", "Analyst");
        manager.tree_view = true;
        let mut target_id = None;
        let render = |events, manager: &mut SnapshotManager, target_id: &mut Option<egui::Id>| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(640.0, 480.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        manager.tree(ui, &tree, 220.0);
                        *target_id = ctx.memory(|memory| memory.focused());
                    });
                },
            )
        };
        let _ = render(Vec::new(), &mut manager, &mut target_id);
        let output = render(Vec::new(), &mut manager, &mut target_id);
        let pos = text_rect(&output, "Desktop ready  (Disk only)").center();
        let _ = render(
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            &mut manager,
            &mut target_id,
        );
        let _ = render(
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
            &mut manager,
            &mut target_id,
        );
        assert_eq!(manager.selected.as_deref(), Some("desktop"));
        let _ = render(
            vec![egui::Event::Key {
                key: egui::Key::Tab,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            &mut manager,
            &mut target_id,
        );
        let _ = render(
            vec![egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            &mut manager,
            &mut target_id,
        );
        assert_eq!(manager.selected.as_deref(), Some("sample"));
        theme::text_size(&ctx, 24.0);
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(640.0, 480.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    assert!(manager.show(ctx, Some(&tree), None, true).is_none());
                },
            );
        }
        let rect = text_rect(&output, "New snapshot…");
        assert!(rect.left() >= 0.0 && rect.right() <= 640.0);
    }

    #[test]
    #[ignore = "requires X11; synthetic snapshot graph, exits automatically"]
    fn native_snapshot_graph_fixture() {
        use std::time::{Duration, Instant};
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct FixtureApp {
            manager: SnapshotManager,
            tree: VmSnapshotTree,
            deadline: Instant,
        }
        impl eframe::App for FixtureApp {
            fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if let Some(command) = self.manager.show(ctx, Some(&self.tree), None, true) {
                    self.manager.result =
                        Some((true, format!("Synthetic fixture action: {command:?}")));
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let small = std::env::var_os("ANTINOMIE_SNAPSHOT_QA_SMALL").is_some();
        let light = std::env::var_os("ANTINOMIE_SNAPSHOT_QA_LIGHT").is_some();
        let font = std::env::var("ANTINOMIE_SNAPSHOT_QA_FONT")
            .ok()
            .and_then(|font| font.parse::<f32>().ok())
            .filter(|font| font.is_finite())
            .unwrap_or(16.0)
            .clamp(12.0, 24.0);
        let seconds = std::env::var("ANTINOMIE_SNAPSHOT_QA_SECONDS")
            .ok()
            .and_then(|seconds| seconds.parse::<u64>().ok())
            .unwrap_or(30)
            .clamp(3, 120);
        eframe::run_native(
            "Antinomie Snapshot UI QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                    [640.0, 480.0]
                } else {
                    [1100.0, 760.0]
                }),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::apply(&cc.egui_ctx, light);
                theme::text_size(&cc.egui_ctx, font);
                let mut manager = SnapshotManager::default();
                manager.bind("vm", "Analyst VM (synthetic)");
                manager.selected = Some("sample".into());
                Ok(Box::new(FixtureApp {
                    manager,
                    tree: fixture(),
                    deadline: Instant::now() + Duration::from_secs(seconds),
                }))
            }),
        )
        .expect("native snapshot fixture");
    }
}
