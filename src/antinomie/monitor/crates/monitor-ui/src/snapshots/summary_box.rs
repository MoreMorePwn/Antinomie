// SPDX-License-Identifier: GPL-3.0-only
//! The Snapshots box on the VM Overview, under Device profile: the VM's
//! checkpoints as a compact tree with Take snapshot, Restore and Open
//! Snapshots. It only draws and asks; the app answers through the snapshot
//! manager's own dialogs, so every rule of the Snapshots window applies
//! (what the VM state allows, a busy operation, compatibility).
use super::{created_time, primary};
use crate::{theme, widgets};
use antinomie_monitor_core::{VmSnapshotMode, VmSnapshotProgress, VmSnapshotTree};
use eframe::egui::{self, RichText};
use egui_phosphor::regular as icon;

/// Set for one frame when a button is pressed; the app takes it.
pub(crate) const ACTION: &str = "summary_snapshots_action";
/// Set by the app before the Overview is drawn: what the manager is doing.
pub(crate) const STATE: &str = "summary_snapshots_state";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Action {
    /// Take snapshot…: the New snapshot dialog.
    Take,
    /// Restore…: the Restore dialog for one checkpoint.
    Restore { id: String, boot_from_disk: bool },
    /// Open Snapshots…: the full window.
    #[default]
    Open,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct BoxState {
    /// A snapshot command is waiting for the backend.
    pub busy: bool,
    /// The last result of the manager, for this VM.
    pub result: Option<(bool, String)>,
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    vm_id: &str,
    tree: Option<&VmSnapshotTree>,
    progress: Option<&VmSnapshotProgress>,
) {
    let state = ui
        .ctx()
        .data(|data| data.get_temp::<BoxState>(egui::Id::new(STATE)))
        .unwrap_or_default();
    let busy = state.busy || progress.is_some();
    let key = egui::Id::new(("summary_snapshots_selected", vm_id));
    let mut selected: Option<String> = ui.ctx().data(|data| data.get_temp(key));
    if let Some(tree) = tree {
        if selected
            .as_ref()
            .is_some_and(|id| !tree.nodes.iter().any(|node| &node.id == id))
        {
            selected = None;
        }
    }
    let mut action = None;
    let capabilities = tree.map(|tree| &tree.capabilities);
    let can_take =
        !busy && capabilities.is_some_and(|caps| caps.can_create_disk || caps.can_create_full);
    let node = selected
        .as_ref()
        .and_then(|id| tree?.nodes.iter().find(|node| &node.id == id));
    let can_restore = !busy
        && capabilities.is_some_and(|caps| caps.can_restore)
        && node.is_some_and(|node| !node.deleted);

    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(icon::CAMERA).size(18.0).color(theme::blue()));
        ui.strong("Snapshots");
        if let Some(tree) = tree {
            let visible = tree.nodes.iter().filter(|node| !node.deleted).count();
            widgets::chip(ui, visible.to_string(), widgets::Tone::Neutral);
        }
    });
    ui.horizontal_wrapped(|ui| {
        let take = ui.add_enabled(can_take, primary("Take snapshot…"));
        if take.clicked() {
            action = Some(Action::Take);
        }
        if !can_take {
            take.on_disabled_hover_text(
                match (busy, capabilities.and_then(|caps| caps.reason.as_deref())) {
                    (true, _) => "A snapshot operation is running",
                    (false, Some(reason)) => reason,
                    (false, None) if tree.is_none() => "Loading snapshots",
                    (false, None) => "This VM cannot be snapshotted now",
                },
            );
        }
        // A disk + memory checkpoint resumes by default; booting its disk is
        // the second choice, as in the Snapshots window.
        let resumes = node.is_some_and(|node| node.mode == VmSnapshotMode::Full && node.compatible);
        let restore = ui.add_enabled(
            can_restore,
            egui::Button::new(if resumes { "Resume…" } else { "Restore…" }),
        );
        if restore.clicked() {
            action = selected.clone().map(|id| Action::Restore {
                id,
                boot_from_disk: !resumes,
            });
        }
        if !can_restore {
            restore.on_disabled_hover_text(if busy {
                "A snapshot operation is running"
            } else if node.is_none() {
                "Select a snapshot to restore"
            } else {
                capabilities
                    .and_then(|caps| caps.reason.as_deref())
                    .unwrap_or("This snapshot cannot be restored now")
            });
        }
        if resumes
            && ui
                .add_enabled(can_restore, egui::Button::new("Restore disk and boot…"))
                .clicked()
        {
            action = selected.clone().map(|id| Action::Restore {
                id,
                boot_from_disk: true,
            });
        }
        if ui
            .button("Open Snapshots…")
            .on_hover_text("The full Snapshots window: graph, rename, delete")
            .clicked()
        {
            action = Some(Action::Open);
        }
    });
    if let Some(progress) = progress {
        ui.horizontal_wrapped(|ui| {
            theme::spinner(ui);
            ui.label(&progress.stage);
        });
    } else if state.busy {
        ui.horizontal_wrapped(|ui| {
            theme::spinner(ui);
            ui.label("Waiting for snapshot operation…");
        });
    }
    if let Some((success, message)) = &state.result {
        if *success {
            ui.colored_label(theme::good(), message);
        } else {
            crate::activity::error_toast(ui, message);
        }
    }
    let Some(tree) = tree else {
        theme::loading_weak(ui, "Loading snapshots…");
        finish(ui, key, selected, action);
        return;
    };
    if let Some(note) = &tree.recovery_note {
        crate::activity::warning(ui, note);
    }
    // The same diagram as the Snapshots window, fitted to the box and drawn
    // with no snapshots too: the base image and the "You are here" node.
    ui.add_space(2.0);
    let body = ui.text_style_height(&egui::TextStyle::Body);
    let height = super::graph::natural_height(tree, body * 6.0, body * 20.0);
    super::graph::paint(
        ui,
        tree,
        &mut selected,
        &mut super::graph::GraphView::default(),
        height,
        false,
    );
    if tree.nodes.is_empty() {
        ui.add(
            egui::Label::new(
                RichText::new("Take snapshot keeps this VM's state so you can return to it.")
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
    } else if let Some(node) = node {
        let mut meta = format!(
            "{} · {} · {}",
            if node.deleted {
                "Hidden checkpoint"
            } else {
                node.name.as_str()
            },
            created_time(node.created_unix_ms),
            crate::values::short_size(node.disk_size + node.memory_size)
        );
        if !node.description.is_empty() && !node.deleted {
            meta.push_str(" · ");
            meta.push_str(node.description.lines().next().unwrap_or_default());
        }
        ui.add(egui::Label::new(RichText::new(meta).small().color(theme::muted())).wrap());
    } else {
        ui.add(
            egui::Label::new(
                RichText::new("Select a snapshot in the diagram to restore it.")
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
    }
    finish(ui, key, selected, action);
}

fn finish(ui: &mut egui::Ui, key: egui::Id, selected: Option<String>, action: Option<Action>) {
    ui.ctx().data_mut(|data| {
        match selected {
            Some(id) => {
                data.insert_temp(key, id);
            }
            None => data.remove::<String>(key),
        }
        if let Some(action) = action {
            data.insert_temp(egui::Id::new(ACTION), action);
        }
    });
}
