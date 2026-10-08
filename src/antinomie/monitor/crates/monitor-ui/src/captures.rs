//! Native process selection and observer history, without program terminals.
use super::{icon, theme};
use antinomie_monitor_core::{
    CaptureScope, CaptureState, CaptureSummary, GuestProcessIdentity, GuestProcessPage,
    PROCESS_PAGE_MAX_COUNT,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

#[derive(Default)]
pub(super) struct ProcessPicker {
    pub open: bool,
    pub after_pid: u32,
    pub selected: Option<GuestProcessIdentity>,
    pub pending: Option<u64>,
}

pub(super) enum ProcessAction {
    Refresh(u32),
    Attach(GuestProcessIdentity),
}

impl ProcessPicker {
    pub fn reset(&mut self) {
        self.after_pid = 0;
        self.selected = None;
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        page: Option<&GuestProcessPage>,
        enabled: bool,
        font_size: f32,
    ) -> Option<ProcessAction> {
        if !self.open {
            return None;
        }
        let mut open = self.open;
        let mut action = None;
        let page = page.filter(|page| page.after_pid == self.after_pid);
        let selection_current = self.selected.as_ref().is_some_and(|identity| {
            page.is_some_and(|page| {
                page.processes
                    .iter()
                    .any(|process| &process.identity == identity)
            })
        });
        // A refreshed/reused PID never inherits the previous row's selection.
        if self.selected.as_ref().is_some_and(|identity| {
            page.is_some_and(|page| {
                page.boot_id != identity.boot_id
                    || !page
                        .processes
                        .iter()
                        .any(|process| &process.identity == identity)
            })
        }) {
            self.selected = None;
        }
        let viewport = ctx.screen_rect();
        let width = 600.0_f32.min((viewport.width() - 64.0).max(200.0));
        egui::Window::new("Attach to process")
            .id(egui::Id::new("attach_process"))
            .open(&mut open)
            .collapsible(false)
            .default_width(width)
            .default_pos(egui::pos2((viewport.width() - width - 16.0) * 0.5, 48.0))
            .max_width((viewport.width() - 64.0).max(200.0))
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    if icon(
                        ui,
                        egui_phosphor::regular::ARROW_CLOCKWISE,
                        "Refresh processes",
                        enabled && self.pending.is_none(),
                    ) {
                        self.reset();
                        action = Some(ProcessAction::Refresh(0));
                    }
                    if icon(
                        ui,
                        egui_phosphor::regular::ARROW_RIGHT,
                        "Next process page",
                        enabled
                            && self.pending.is_none()
                            && page.is_some_and(|page| page.next_pid != 0),
                    ) {
                        if let Some(page) = page {
                            self.after_pid = page.next_pid;
                            self.selected = None;
                            action = Some(ProcessAction::Refresh(self.after_pid));
                        }
                    }
                    ui.label(if self.pending.is_some() {
                        "Reading processes..."
                    } else {
                        "Guest processes"
                    });
                });
                let height = (viewport.height() - 300.0).clamp(64.0, 360.0);
                egui::ScrollArea::horizontal()
                    .id_salt("process_columns")
                    .show(ui, |ui| {
                        ui.set_min_width(440.0_f32.max(font_size * 20.0));
                        TableBuilder::new(ui)
                            .id_salt("process_picker")
                            .sense(egui::Sense::click())
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::exact(72.0_f32.max(font_size * 4.0)))
                            .column(Column::remainder().at_least(150.0))
                            .column(Column::exact(72.0_f32.max(font_size * 4.0)))
                            .column(Column::exact(90.0_f32.max(font_size * 5.0)))
                            .striped(true)
                            .max_scroll_height(height)
                            .min_scrolled_height(0.0)
                            .header(font_size + 12.0, |mut header| {
                                for label in ["PID", "Name", "UID", "Threads"] {
                                    header.col(|ui| {
                                        ui.strong(label);
                                    });
                                }
                            })
                            .body(|body| {
                                let processes = page
                                    .map(|page| page.processes.as_slice())
                                    .unwrap_or_default();
                                body.rows(
                                    font_size + 14.0,
                                    processes.len().min(PROCESS_PAGE_MAX_COUNT as usize),
                                    |mut row| {
                                        let process = &processes[row.index()];
                                        row.set_selected(
                                            self.selected.as_ref() == Some(&process.identity),
                                        );
                                        for text in [
                                            process.identity.tgid.to_string(),
                                            process.command.clone(),
                                            process.uid.to_string(),
                                            process.thread_count.to_string(),
                                        ] {
                                            row.col(|ui| {
                                                ui.add(
                                                    egui::Label::new(&text)
                                                        .selectable(false)
                                                        .truncate(),
                                                )
                                                .on_hover_text(&text);
                                            });
                                        }
                                        if row.response().clicked() && self.pending.is_none() {
                                            self.selected = Some(process.identity.clone());
                                        }
                                    },
                                );
                            });
                    });
                if let Some(identity) = &self.selected {
                    ui.add(
                        egui::Label::new(format!(
                            "PID {} | task {} | start {} ns",
                            identity.tgid, identity.task_cookie, identity.start_boot_ns
                        ))
                        .truncate(),
                    )
                    .on_hover_text(format!("Boot {}", identity.boot_id));
                }
                if !enabled {
                    ui.colored_label(theme::WARN, "Process attachment unavailable");
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            enabled && self.pending.is_none() && selection_current,
                            egui::Button::new(format!("{} Attach", egui_phosphor::regular::PLUG)),
                        )
                        .clicked()
                    {
                        if let Some(identity) = self.selected.clone() {
                            action = Some(ProcessAction::Attach(identity));
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        self.open = false;
                    }
                });
            });
        self.open &= open;
        action
    }
}

pub(super) fn status(state: CaptureState) -> &'static str {
    match state {
        CaptureState::Unknown => "Unknown outcome",
        CaptureState::Active => "Active",
        CaptureState::Stopped => "Stopped; tails may arrive",
        CaptureState::Finalized => "Finalized",
    }
}

pub(super) fn scope(scope: &CaptureScope) -> String {
    match scope {
        CaptureScope::Process { root } => format!("PID {} and future descendants", root.tgid),
        CaptureScope::AllUserspace => "All guest programs".into(),
    }
}

pub(super) fn history(
    ui: &mut egui::Ui,
    captures: &[CaptureSummary],
    selected: Option<&str>,
    font_size: f32,
) -> Option<(String, bool)> {
    let mut action = None;
    let height = (ui.available_height() * 0.58).max(70.0);
    egui::ScrollArea::horizontal()
        .id_salt("capture_columns")
        .show(ui, |ui| {
            ui.set_min_width(400.0);
            TableBuilder::new(ui)
                .id_salt("capture_history")
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder().at_least(180.0))
                .column(Column::exact(205.0))
                .striped(true)
                .max_scroll_height(height)
                .min_scrolled_height(0.0)
                .header(font_size + 12.0, |mut header| {
                    for label in ["Capture", "State"] {
                        header.col(|ui| {
                            ui.strong(label);
                        });
                    }
                })
                .body(|body| {
                    body.rows(font_size + 14.0, captures.len(), |mut row| {
                        let capture = &captures[row.index()];
                        row.set_selected(selected == Some(capture.id.as_str()));
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(scope(&capture.scope))
                                    .selectable(false)
                                    .truncate(),
                            )
                            .on_hover_text(&capture.id);
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(status(capture.state))
                                    .selectable(false)
                                    .truncate(),
                            )
                            .on_hover_text(status(capture.state));
                        });
                        let response = row.response();
                        if response.clicked() || response.double_clicked() {
                            action = Some((capture.id.clone(), response.double_clicked()));
                        }
                    });
                });
        });
    ui.separator();
    if let Some(capture) = selected.and_then(|id| captures.iter().find(|capture| capture.id == id))
    {
        egui::ScrollArea::both()
            .id_salt("capture_metadata")
            .show(ui, |ui| {
                egui::Grid::new("capture_identity")
                    .num_columns(2)
                    .show(ui, |ui| {
                        for (label, value) in [
                            ("Scope", scope(&capture.scope)),
                            ("State", status(capture.state).to_owned()),
                            ("Capture", capture.id.clone()),
                            ("Boot", capture.boot_id.clone()),
                            ("Observer cookie", capture.capture_cookie.to_string()),
                            (
                                "Start",
                                capture
                                    .start_ns
                                    .map_or_else(|| "Unknown".into(), |time| format!("{time} ns")),
                            ),
                            (
                                "Stop",
                                capture.stop_ns.map_or_else(
                                    || "Not acknowledged".into(),
                                    |time| format!("{time} ns"),
                                ),
                            ),
                            ("Recording", capture.directory.display().to_string()),
                        ] {
                            ui.label(label);
                            ui.add(egui::Label::new(value).selectable(true));
                            ui.end_row();
                        }
                        if let CaptureScope::Process { root } = &capture.scope {
                            ui.label("Root task / start");
                            ui.label(format!("{} / {} ns", root.task_cookie, root.start_boot_ns));
                            ui.end_row();
                        }
                    });
                for warning in [&capture.incomplete_reason, &capture.recording_error]
                    .into_iter()
                    .flatten()
                {
                    ui.label(RichText::new(warning).color(theme::WARN));
                }
            });
    } else if captures.is_empty() {
        ui.colored_label(theme::MUTED, "No retained captures for this VM");
    }
    action
}
