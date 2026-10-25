// SPDX-License-Identifier: GPL-3.0-only
//! Processes of the session: the program and the children of its forks, the
//! prompt shown when the program forks and the policy for the next fork.
use super::*;
use crate::{
    table_sort,
    widgets::table::{self, Cell, Mark},
};
use antinomie_monitor_core::debug::view::{FollowMode, ForkChoice, ForkPolicy, InferiorState};

use egui_extras::{Column, TableBuilder};

const FOLLOW_MODES: [FollowMode; 4] = [
    FollowMode::Off,
    FollowMode::Parent,
    FollowMode::Child,
    FollowMode::Ask,
];

/// The state of one process in words.
pub(super) fn state_text(state: InferiorState) -> String {
    match state {
        InferiorState::Running => "running".into(),
        InferiorState::Stopped(reason) => format!("stopped ({reason})"),
        InferiorState::Held => "held".into(),
        InferiorState::Exited(status) if status & 0x7f == 0 => {
            format!("exited ({})", (status >> 8) & 0xff)
        }
        InferiorState::Exited(status) => format!("killed (signal {})", status & 0x7f),
    }
}

/// The banner shown above the columns while the program waits for a choice.
pub(super) fn fork_prompt(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let Some(prompt) = view.fork_prompt else {
        return;
    };
    let enabled = view.app_controls();
    egui::Frame::group(ui.style())
        .stroke(egui::Stroke::new(1.5_f32, theme::warn()))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "Process {} {} child {}",
                        prompt.parent,
                        if prompt.vfork { "vforked" } else { "forked" },
                        prompt.child
                    ))
                    .strong()
                    .color(theme::warn()),
                );
                let mut detach_other = !panel.prompt_hold_other;
                let mut choose =
                    |ui: &mut egui::Ui, label: &str, follow: ForkChoice, detach_other: bool| {
                        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                            actions.push(PanelAction::Debug(DebugAction::ForkDecision {
                                follow,
                                detach_other,
                            }));
                        }
                    };
                choose(ui, "Follow parent", ForkChoice::Parent, detach_other);
                choose(ui, "Follow child", ForkChoice::Child, detach_other);
                ui.add_enabled(
                    enabled,
                    egui::Checkbox::new(&mut detach_other, "Let the other process run"),
                );
                panel.prompt_hold_other = !detach_other;
            });
        });
}

/// The Processes pane: a sortable table of the program and its forked
/// children, and the fork policy chooser.
pub(super) fn pane(ui: &mut egui::Ui, view: &DebugView, actions: &mut Vec<PanelAction>) {
    let enabled = view.app_controls();
    if view.inferiors.len() <= 1 && !view.caps.follow {
        ui.weak("One process; this guest base cannot follow forks.");
        return;
    }
    const TABLE: &str = "debugger-processes";
    let order = table_sort::order(ui.ctx(), TABLE, view.inferiors.len(), |column, a, b| {
        let (a, b) = (&view.inferiors[a], &view.inferiors[b]);
        match column {
            0 => a.pid.cmp(&b.pid),
            1 => a.parent.cmp(&b.parent),
            _ => state_text(a.state).cmp(&state_text(b.state)),
        }
    });
    let row_height = table::row_height(egui::TextStyle::Body.resolve(ui.style()).size);
    table::begin(ui);
    TableBuilder::new(ui)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .id_salt(TABLE)
        .striped(true)
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(60.0))
        .column(Column::auto().at_least(110.0))
        .column(Column::remainder().at_least(120.0))
        .vscroll(false)
        .header(row_height + 4.0, |mut header| {
            for (column, title) in ["PID", "Parent", "State"].into_iter().enumerate() {
                header.col(|ui| table_sort::header(ui, TABLE, column, title));
            }
            header.col(|ui| table::head(ui, ""));
        })
        .body(|body| {
            body.rows(row_height, order.len(), |mut row| {
                let inferior = &view.inferiors[order[row.index()]];
                let exited = matches!(inferior.state, InferiorState::Exited(_));
                row.set_selected(inferior.selected);
                row.col(|ui| {
                    table::row_mark(
                        ui,
                        if inferior.selected {
                            Mark::Selected
                        } else {
                            Mark::None
                        },
                    );
                    table::cell(ui, Cell::Mono, &inferior.pid.to_string());
                });
                row.col(|ui| {
                    let parent = inferior.parent.map(|parent| parent.to_string());
                    table::cell(ui, Cell::Mono, parent.as_deref().unwrap_or("–"));
                });
                row.col(|ui| {
                    let text = if inferior.vfork {
                        format!("vfork, {}", state_text(inferior.state))
                    } else {
                        state_text(inferior.state)
                    };
                    let text = RichText::new(text);
                    table::cell_rich(
                        ui,
                        Cell::Text,
                        if exited {
                            text.color(theme::muted())
                        } else {
                            text
                        },
                    );
                });
                row.col(|ui| {
                    if !inferior.selected
                        && ui
                            .add_enabled(enabled, egui::Button::new("Show").small())
                            .on_hover_text("Show this process's registers, memory and breakpoints")
                            .clicked()
                    {
                        actions.push(PanelAction::Debug(DebugAction::SelectInferior {
                            pid: inferior.pid,
                        }));
                    }
                    if ui
                        .add_enabled(enabled && !exited, egui::Button::new("Let go").small())
                        .on_hover_text("Stop debugging this process; it then runs free")
                        .clicked()
                    {
                        actions.push(PanelAction::Debug(DebugAction::DetachInferior {
                            pid: inferior.pid,
                        }));
                    }
                });
            });
        });
    ui.add_space(4.0);
    policy(ui, view, enabled, actions);
}

fn policy(ui: &mut egui::Ui, view: &DebugView, enabled: bool, actions: &mut Vec<PanelAction>) {
    let usable = enabled && view.caps.follow;
    let current = view.fork_policy;
    let mut next: Option<ForkPolicy> = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("At a fork").color(theme::muted()));
        ui.add_enabled_ui(usable, |ui| {
            egui::ComboBox::from_id_salt("debugger-fork-follow")
                .selected_text(current.follow.label())
                .show_ui(ui, |ui| {
                    for mode in FOLLOW_MODES {
                        if ui
                            .selectable_label(current.follow == mode, mode.label())
                            .clicked()
                            && current.follow != mode
                        {
                            next = Some(ForkPolicy {
                                follow: mode,
                                ..current
                            });
                        }
                    }
                });
            let mut detach = current.detach_other;
            if ui
                .checkbox(&mut detach, "Let the other process run")
                .changed()
            {
                next = Some(ForkPolicy {
                    detach_other: detach,
                    ..current
                });
            }
        })
        .response
        .on_disabled_hover_text(if view.caps.follow {
            "An external debugger controls the process"
        } else {
            "This guest base cannot follow forks"
        });
    });
    if let Some(policy) = next {
        actions.push(PanelAction::Debug(DebugAction::SetForkPolicy(policy)));
    }
}
