// SPDX-License-Identifier: GPL-3.0-only
//! The Snapshots box on the VM Summary, under Device profile: the VM's
//! checkpoints as a compact tree with Take snapshot, Restore and Open
//! Snapshots. It only draws and asks; the app answers through the snapshot
//! manager's own dialogs, so every rule of the Snapshots window applies
//! (what the VM state allows, a busy operation, compatibility).
use super::{created_time, graph_layout, mode_label, primary};
use crate::{theme, widgets};
use antinomie_monitor_core::{VmSnapshotMode, VmSnapshotProgress, VmSnapshotTree};
use eframe::egui::{self, RichText};
use egui_phosphor::regular as icon;

/// Set for one frame when a button is pressed; the app takes it.
pub(crate) const ACTION: &str = "summary_snapshots_action";
/// Set by the app before the Summary is drawn: what the manager is doing.
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
    if tree.nodes.is_empty() {
        ui.add(
            egui::Label::new(
                RichText::new(
                    "No snapshots: Take snapshot keeps this VM's state so you can return to it.",
                )
                .color(theme::muted()),
            )
            .wrap(),
        );
        finish(ui, key, selected, action);
        return;
    }
    ui.add_space(2.0);
    let body = ui.text_style_height(&egui::TextStyle::Body);
    egui::ScrollArea::vertical()
        .id_salt(("summary_snapshots_list", vm_id))
        // The box sits in a horizontal row, which offers a single line of
        // height: ask for the room explicitly.
        .max_height(body * 16.0)
        .min_scrolled_height(body * 12.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Base image").strong().color(theme::text()));
                if tree.active_parent_id.is_none() {
                    current_chip(ui);
                }
            });
            let items = graph_layout(tree);
            let depths: Vec<_> = items.iter().map(|item| item.depth + 1).collect();
            let mono = egui::TextStyle::Monospace.resolve(ui.style());
            let char_width = crate::tree_lines::char_width(ui, &mono);
            for (item, branch) in items.iter().zip(crate::tree_lines::prefixes(&depths)) {
                let node = &tree.nodes[item.index];
                crate::tree_lines::row(ui, &branch, char_width, |ui| {
                    ui.vertical(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            let name = if node.deleted {
                                "Hidden checkpoint"
                            } else {
                                node.name.as_str()
                            };
                            let response = ui.add(egui::SelectableLabel::new(
                                selected.as_deref() == Some(node.id.as_str()),
                                name,
                            ));
                            if response.clicked() {
                                selected = Some(node.id.clone());
                            }
                            widgets::chip(
                                ui,
                                mode_label(node.mode),
                                if node.mode == VmSnapshotMode::Full {
                                    widgets::Tone::Info
                                } else {
                                    widgets::Tone::Neutral
                                },
                            );
                            if tree.active_parent_id.as_deref() == Some(node.id.as_str()) {
                                current_chip(ui);
                            }
                        });
                        let mut meta = format!(
                            "{} · {}",
                            created_time(node.created_unix_ms),
                            crate::values::short_size(node.disk_size + node.memory_size)
                        );
                        if !node.description.is_empty() && !node.deleted {
                            meta.push_str(" · ");
                            meta.push_str(node.description.lines().next().unwrap_or_default());
                        }
                        ui.add(
                            egui::Label::new(RichText::new(meta).small().color(theme::muted()))
                                .wrap(),
                        )
                        .on_hover_text(&node.description);
                    });
                });
            }
        });
    finish(ui, key, selected, action);
}

/// The marker of the checkpoint the next snapshot hangs from.
fn current_chip(ui: &mut egui::Ui) {
    widgets::chip(ui, "Current", widgets::Tone::Good)
        .on_hover_text("The VM runs from here; a new snapshot branches from this one");
}

fn finish(ui: &mut egui::Ui, key: egui::Id, selected: Option<String>, action: Option<Action>) {
    ui.ctx().data_mut(|data| {
        match selected {
            Some(id) => data.insert_temp(key, id),
            None => data.remove::<String>(key),
        }
        if let Some(action) = action {
            data.insert_temp(egui::Id::new(ACTION), action);
        }
    });
}
