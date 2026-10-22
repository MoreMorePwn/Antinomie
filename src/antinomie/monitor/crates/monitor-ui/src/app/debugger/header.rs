// SPDX-License-Identifier: GPL-3.0-only
//! The panel's top: process and thread, the stop status line, run-control
//! buttons and the endpoint an external debugger connects to.
use super::*;
use antinomie_monitor_core::debug::view::{Controller, Pending, RunState};

/// The status line: text, its color, and whether to show a spinner.
pub(super) fn status_line(view: &DebugView) -> (String, egui::Color32, bool) {
    if view.controller == Controller::Gdb {
        return (
            "Controlled by gdb (read-only here until it disconnects)".into(),
            theme::warn(),
            false,
        );
    }
    match &view.run {
        RunState::Unknown => ("Reading the process state…".into(), theme::muted(), true),
        RunState::Stopped { reason, pc, .. } => (
            format!("Stopped: {reason} @ {pc:#x}"),
            theme::value(theme::ValueKind::Pointer),
            view.loading,
        ),
        RunState::Running {
            pending: Pending::Nothing,
        } => ("Running".into(), theme::good(), false),
        RunState::Running {
            pending: Pending::Stopping,
        } => ("Stopping…".into(), theme::muted(), true),
        RunState::Running {
            pending: Pending::Stepping,
        } => ("Stepping…".into(), theme::muted(), true),
        RunState::Exited { wait_status } => (
            if wait_status & 0x7f == 0 {
                format!("Exited with status {}", (wait_status >> 8) & 0xff)
            } else {
                format!("Killed by signal {}", wait_status & 0x7f)
            },
            theme::error(),
            false,
        ),
        RunState::Replaced => (
            "The process ran a new program; this session is over".into(),
            theme::error(),
            false,
        ),
    }
}

pub(super) fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    info: &DebugSessionInfo,
    view: Option<&DebugView>,
    actions: &mut Vec<PanelAction>,
) {
    let live =
        view.is_some_and(|view| view.app_controls() && !view.run.is_over()) && info.ended.is_none();
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Process").color(theme::muted()));
        ui.label(format!("PID {} · {}", info.target.tgid, info.architecture));
        if let Some(view) = view {
            thread_selector(ui, panel, view, actions);
            let (text, color, spinner) = status_line(view);
            if spinner {
                theme::spinner(ui);
            }
            let status = ui.label(RichText::new(text).color(color));
            if let RunState::Stopped { tid, sequence, .. } = &view.run {
                status.on_hover_text(format!("Thread {tid} stopped, stop {sequence}"));
            }
            if let Some(chip) = panes::driving_chip(Some(view)) {
                crate::widgets::chip(ui, chip, crate::widgets::Tone::Warn);
            }
            if panel.waiting(view) {
                theme::loading_weak(ui, "Working…");
            }
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let stopped = view.is_some_and(|view| view.run.stopped_sequence().is_some());
        let running = view.is_some_and(|view| {
            matches!(
                view.run,
                RunState::Running {
                    pending: Pending::Nothing | Pending::Stepping
                }
            )
        });
        let idle = view.is_some_and(|view| !panel.waiting(view) && !view.loading);
        let can = live && idle;
        let tid = view.and_then(|view| view.selected_tid);
        let button = |ui: &mut egui::Ui, enabled: bool, label: String, tip: &str| {
            ui.add_enabled(enabled, egui::Button::new(label))
                .on_hover_text(tip)
                .on_disabled_hover_text(disabled_reason(view, stopped))
                .clicked()
        };
        if button(
            ui,
            can && stopped,
            format!("{} Continue", egui_phosphor::regular::PLAY),
            "Resume every thread",
        ) {
            actions.push(PanelAction::Debug(DebugAction::Continue));
        }
        let step = button(
            ui,
            can && stopped && tid.is_some() && view.is_some_and(|view| view.caps.single_step),
            format!("{} Step", egui_phosphor::regular::ARROW_BEND_DOWN_RIGHT),
            "Run one instruction of the selected thread; the other threads stay stopped",
        );
        if let (true, Some(tid)) = (step, tid) {
            actions.push(PanelAction::Debug(DebugAction::Step { tid }));
        }
        if button(
            ui,
            live && running && view.is_some_and(|view| !panel.waiting(view)),
            format!("{} Stop", egui_phosphor::regular::STOP),
            "Stop every thread of the process",
        ) {
            actions.push(PanelAction::Debug(DebugAction::Stop));
        }
        if button(
            ui,
            can && stopped,
            format!("{} Refresh", egui_phosphor::regular::ARROWS_CLOCKWISE),
            "Read the registers and memory again",
        ) {
            actions.push(PanelAction::Debug(DebugAction::Refresh));
        }
        ui.separator();
        if ui
            .button("Detach")
            .on_hover_text("Remove breakpoints; the process keeps running")
            .clicked()
        {
            actions.push(PanelAction::Detach { kill: false });
        }
        if ui
            .button("Detach and kill")
            .on_hover_text("Ends the process with SIGKILL")
            .clicked()
        {
            actions.push(PanelAction::Detach { kill: true });
        }
    });
    endpoint(ui, info);
}

fn disabled_reason(view: Option<&DebugView>, stopped: bool) -> &'static str {
    match view {
        None => "The debug engine has not answered yet",
        Some(view) if !view.app_controls() => "An external debugger controls the process",
        Some(view) if view.run.is_over() => "The process has ended",
        Some(_) if !stopped => "Stop the process first",
        Some(_) => "Waiting for the previous request",
    }
}

fn thread_selector(
    ui: &mut egui::Ui,
    panel: &DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let enabled =
        view.app_controls() && view.run.stopped_sequence().is_some() && !panel.waiting(view);
    ui.add_enabled_ui(enabled, |ui| {
        let current = view.selected_tid;
        egui::ComboBox::from_id_salt("debugger-thread")
            .selected_text(match current {
                Some(tid) => format!("Thread {tid}"),
                None => "Thread".into(),
            })
            .show_ui(ui, |ui| {
                for thread in &view.threads {
                    let selected = Some(thread.tid) == current;
                    if ui
                        .selectable_label(selected, format!("Thread {}", thread.tid))
                        .clicked()
                        && !selected
                    {
                        actions.push(PanelAction::Debug(DebugAction::SelectThread {
                            tid: thread.tid,
                        }));
                    }
                }
            });
    });
}

/// How to reach the same process from gdb, IDA, Ghidra or radare2, and the
/// rule that decides who controls it. The unix socket and the rule sit behind
/// "More", so the tab keeps its height for the listing.
fn endpoint(ui: &mut egui::Ui, info: &DebugSessionInfo) {
    let more_id = egui::Id::new("debugger-endpoint-more");
    let mut more = ui
        .data(|data| data.get_temp::<bool>(more_id))
        .unwrap_or(false);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Endpoint").color(theme::muted()));
        ui.add(egui::Label::new(RichText::new(&info.gdb_command).monospace()).selectable(true));
        if icon(ui, egui_phosphor::regular::COPY, "Copy command", true) {
            ui.ctx().copy_text(info.gdb_command.clone());
        }
        if info.client_connected {
            ui.label(RichText::new("Client").color(theme::muted()));
            ui.label("connected");
        }
        if crate::widgets::link(
            ui,
            if more {
                "Less"
            } else {
                "Other ways to connect"
            },
        )
        .clicked()
        {
            more = !more;
        }
    });
    ui.data_mut(|data| data.insert_temp(more_id, more));
    if more {
        ui.label(RichText::new("gdb (Unix socket, needs socat)").color(theme::muted()));
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::Label::new(RichText::new(&info.gdb_unix_command).monospace())
                    .selectable(true),
            );
            if icon(ui, egui_phosphor::regular::COPY, "Copy command", true) {
                ui.ctx().copy_text(info.gdb_unix_command.clone());
            }
        });
        ui.add(
            egui::Label::new(
                "One controller at a time. This panel drives the process until a debugger \
                 connects; the connecting debugger takes control (the process is stopped) and \
                 this panel becomes read-only until it disconnects, which leaves the process \
                 running. Breakpoints set here stay set. Connections are local to this computer.",
            )
            .wrap(),
        );
    }
}
