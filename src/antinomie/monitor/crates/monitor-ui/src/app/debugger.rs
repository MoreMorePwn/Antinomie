// SPDX-License-Identifier: GPL-3.0-only
//! Attach the debugger to a running guest process and show how to reach it.
//! The engine is in the guest kernel and the RSP server on the host; the
//! Debugger tab beside Static Analysis starts and ends the session, shows how
//! to reach it from gdb, and is the in-app debugger: run control, the listing
//! around the instruction pointer with the registers, and folded panes for
//! threads, processes, breakpoints, memory, stack, signals and a gdb console.
use super::*;
use antinomie_monitor_core::{
    debug::view::{DebugAction, DebugView},
    DebugSessionInfo,
};

mod code;
mod console;
mod data;
mod header;
pub(super) mod lists;
pub(crate) mod panes;
pub(super) mod prefs;
mod processes;
mod pty;
mod signals;
mod state;

pub(crate) use console::{is_console_tool, GdbFlavour};
pub(crate) use prefs::DebuggerPrefs;
pub(crate) use state::DebuggerPanel;

/// Something the panel asks of the app once the tab has been drawn.
pub(super) enum PanelAction {
    Detach {
        kill: bool,
    },
    Debug(DebugAction),
    /// Library, Analysis tools: where gdb front ends are installed.
    OpenTools,
    /// Settings, Analysis tools: where the front end is chosen.
    OpenSettings,
}

impl MonitorApp {
    /// Why the debugger cannot be attached now, if it cannot.
    pub(super) fn debugger_unavailable(&self) -> Option<&'static str> {
        if !self.running() || self.closing || self.selected.is_none() {
            Some("Start the selected VM to debug a process.")
        } else if self.snapshot.memory_dump.is_some() {
            Some("Wait for the VM RAM dump to finish; the guest is paused.")
        } else if !self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 17))
        {
            Some("The debugger needs a guest base with revision 17 or newer.")
        } else if self.snapshot.debug.is_some() {
            Some("A debugger is already attached; detach it first.")
        } else {
            None
        }
    }

    pub(super) fn open_debug_picker(&mut self) {
        if self.debugger_unavailable().is_some() {
            return;
        }
        self.process_picker.purpose = captures::ProcessPurpose::Debug;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
    }

    /// Whether a debugger session is attached, which is when its tab exists.
    pub(crate) fn debugger_attached(&self) -> bool {
        self.snapshot.debug.is_some()
    }

    /// Once per frame, tab shown or not: follow the session and send the
    /// remembered choices when a new one begins.
    pub(super) fn debugger_session(&mut self) {
        let Some(info) = self.snapshot.debug.clone() else {
            self.debugger.track_session(None);
            return;
        };
        self.debugger.track_session(Some(u64::from(info.tcp_port)));
        let view = self.debug_view();
        if let Some(view) = &view {
            if view.app_controls() && self.debugger.take_announce() {
                let prefs = self.settings.debugger.clone();
                let policy = prefs.fork_policy();
                self.debug_action_quiet(view, DebugAction::SetSignalTable(prefs.signals));
                self.debug_action_quiet(view, DebugAction::SetForkPolicy(policy));
            }
            self.debugger.prune(view);
        }
    }

    /// The tab body of the attached session.
    pub(super) fn debugger_tab(&mut self, ui: &mut egui::Ui) {
        let Some(info) = self.snapshot.debug.clone() else {
            ui.weak("No debugger session. Attach one from Run, Attach debugger…");
            return;
        };
        let view = self.debug_view();
        let mut actions = Vec::new();
        let ended_session = info.ended.is_some();
        let env = console::Env {
            tools: &self.snapshot.analysis_tools,
            data_dir: &self.options.data_dir,
            flavour: self.settings.debugger.gdb_flavour,
            port: info.tcp_port,
            ended_session,
        };
        show(
            ui,
            &mut self.debugger,
            &mut self.settings.debugger,
            &env,
            &info,
            view.as_deref(),
            &mut actions,
        );
        for action in actions {
            match action {
                // Killing the process is asked about first.
                PanelAction::Detach { kill: true } => self.confirm = Some(Confirm::DebugKill),
                PanelAction::Detach { kill: false } => {
                    self.send(Command::DebugDetach { kill: false })
                }
                PanelAction::Debug(action) => {
                    if let Some(view) = &view {
                        self.remember_debug_choice(&action);
                        self.debug_action(view, action);
                    }
                }
                PanelAction::OpenTools => self.open_library(crate::workspace::LibraryPage::Tools),
                PanelAction::OpenSettings => {
                    self.settings_open = true;
                    self.settings_page = settings_window::SettingsPage::AnalysisTools;
                }
            }
        }
    }
}

impl MonitorApp {
    /// Keep a signal or fork choice the user made for later sessions.
    pub(super) fn remember_debug_choice(&mut self, action: &DebugAction) {
        let prefs = &mut self.settings.debugger;
        match action {
            DebugAction::SetSignalPolicy { signal, action } => {
                prefs.signals.set(*signal, *action);
            }
            DebugAction::SetSignalTable(table) => prefs.signals = table.clone().sanitized(),
            DebugAction::SetForkPolicy(policy) => prefs.remember_policy(*policy),
            _ => {}
        }
    }
}

/// The whole tab: header, the listing with the registers, and the folded
/// panes under them.
fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    prefs: &mut DebuggerPrefs,
    env: &console::Env<'_>,
    info: &DebugSessionInfo,
    view: Option<&DebugView>,
    actions: &mut Vec<PanelAction>,
) {
    header::show(ui, panel, info, view, actions);
    if let Some(ended) = &info.ended {
        crate::activity::warning(ui, format!("Session ended: {ended}"));
    }
    let Some(view) = view else {
        theme::loading_weak(ui, "Connecting to the debug engine…");
        return;
    };
    if let Some(notice) = &view.notice {
        crate::activity::warning(ui, notice);
    }
    if let Some(problem) = panel.input_error.clone() {
        crate::activity::warning(ui, problem);
    }
    processes::fork_prompt(ui, panel, view, actions);
    ui.separator();
    // The strip is always there; its content area has height only while a
    // pane is open (and then keeps the height the user dragged it to).
    let open = panes::open(prefs);
    // The panes never take more than 60% of what is left, so the listing
    // stays in view whatever is open; the height dragged to is kept.
    let room = ui.available_height();
    let mut bottom =
        egui::TopBottomPanel::bottom(egui::Id::new(("debugger-panes", !open.is_empty())))
            .resizable(!open.is_empty())
            .frame(egui::Frame::new());
    if !open.is_empty() {
        bottom = bottom
            .default_height(
                (room
                    * if prefs.pane_open(panes::Pane::Console) {
                        0.55
                    } else {
                        0.4
                    })
                .clamp(150.0, 420.0),
            )
            .height_range(120.0..=(room * 0.6).max(150.0));
    }
    bottom.show_inside(ui, |ui| {
        if let Some(clicked) = panes::strip(ui, prefs, Some(view), panel.console.running()) {
            prefs.toggle_pane(clicked);
        }
        if !open.is_empty() {
            panes::show(ui, &open, |ui, pane| match pane {
                panes::Pane::Threads => lists::threads(ui, panel, view, actions),
                panes::Pane::Processes => processes::pane(ui, view, actions),
                panes::Pane::Breakpoints => lists::breakpoints(ui, panel, view, actions),
                panes::Pane::Memory => data::memory_pane(ui, panel, view, actions),
                panes::Pane::Stack => data::stack_pane(ui, view),
                panes::Pane::Signals => signals::pane(ui, view, actions),
                panes::Pane::Console => console::show(ui, &mut panel.console, env, actions),
            });
        }
    });
    egui::CentralPanel::default()
        .frame(egui::Frame::new())
        .show_inside(ui, |ui| {
            use egui_extras::{Size, StripBuilder};
            StripBuilder::new(ui)
                .size(Size::remainder().at_least(360.0))
                .size(Size::relative(0.3).at_least(240.0).at_most(380.0))
                .horizontal(|mut strip| {
                    strip.cell(|ui| code::show(ui, panel, view, actions));
                    strip.cell(|ui| data::registers_column(ui, view));
                });
        });
}
