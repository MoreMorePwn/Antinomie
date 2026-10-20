// SPDX-License-Identifier: MIT
//! Processes of the session: the program and the children of its forks, the
//! prompt shown when the program forks and the policy for the next fork.
use super::*;
use antinomie_monitor_core::debug::view::{
    FollowMode, ForkChoice, ForkPolicy, InferiorState, InferiorView,
};

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

fn row_text(inferior: &InferiorView) -> String {
    let mut text = format!(
        "{}{}",
        if inferior.selected { ">" } else { " " },
        inferior.pid
    );
    if let Some(parent) = inferior.parent {
        text.push_str(&format!("  child of {parent}"));
    }
    if inferior.vfork {
        text.push_str("  vfork");
    }
    text.push_str(&format!("  {}", state_text(inferior.state)));
    text
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

/// The Processes section: the list and the fork policy chooser.
pub(super) fn section(ui: &mut egui::Ui, view: &DebugView, actions: &mut Vec<PanelAction>) {
    if view.inferiors.len() <= 1 && !view.caps.follow {
        return;
    }
    let enabled = view.app_controls();
    theme::section(ui, "Processes");
    for inferior in &view.inferiors {
        ui.horizontal(|ui| {
            let text = RichText::new(row_text(inferior)).monospace();
            let text = if matches!(inferior.state, InferiorState::Exited(_)) {
                text.color(theme::muted())
            } else {
                text
            };
            let _ = ui.selectable_label(inferior.selected, text);
            let exited = matches!(inferior.state, InferiorState::Exited(_));
            if !inferior.selected
                && ui
                    .add_enabled(enabled, egui::Button::new("Show"))
                    .on_hover_text("Show this process's registers, memory and breakpoints")
                    .clicked()
            {
                actions.push(PanelAction::Debug(DebugAction::SelectInferior {
                    pid: inferior.pid,
                }));
            }
            if ui
                .add_enabled(enabled && !exited, egui::Button::new("Let go"))
                .on_hover_text("Stop debugging this process; it then runs free")
                .clicked()
            {
                actions.push(PanelAction::Debug(DebugAction::DetachInferior {
                    pid: inferior.pid,
                }));
            }
        });
    }
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
