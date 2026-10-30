//! Native process selection and observer history, without program terminals.
use super::{icon, theme, values};
use antinomie_monitor_core::{
    capture_processes::CaptureProcess, CaptureScope, CaptureState, CaptureSummary,
    GuestProcessIdentity, GuestProcessPage, WaitStatus,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::sync::Arc;

mod layout;

const PROCESS_FIELDS: &[crate::query::FieldSpec<'static>] = &[
    crate::query::FieldSpec::number("pid", "Guest process ID"),
    crate::query::FieldSpec::text("name", "Guest command name"),
    crate::query::FieldSpec::number("uid", "Guest user ID"),
    crate::query::FieldSpec::number("threads", "Thread count"),
];

#[derive(Default)]
pub(super) struct ProcessPicker {
    pub purpose: ProcessPurpose,
    pub open: bool,
    pub after_pid: u32,
    pub selected: Option<GuestProcessIdentity>,
    pub pending: Option<u64>,
    /// Name or PID text the list is narrowed to.
    pub filter: String,
    /// Dump core: the budget (bytes) and deadline the request will carry, and the
    /// budget the user picked, which becomes the remembered default.
    pub core_budget: u32,
    pub core_timeout_ms: u32,
    pub core_picked: Option<u32>,
    /// Why the action is not available, said in the window; set each frame.
    pub unavailable: Option<&'static str>,
}

/// What the Dump core dialog needs to know about the guest.
#[derive(Clone, Copy)]
pub(super) struct CoreContext {
    pub limits: Option<antinomie_monitor_core::CoreLimits>,
    pub default_mib: u32,
    /// Guest MemAvailable, when a recent sample says.
    pub available: Option<u64>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ProcessPurpose {
    #[default]
    Attach,
    Core,
    Debug,
}

pub(super) enum ProcessAction {
    Refresh(u32),
    Attach(GuestProcessIdentity),
    DumpCore(GuestProcessIdentity, u32, u32),
    Debug(GuestProcessIdentity),
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
        core_context: CoreContext,
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
        let core = self.purpose == ProcessPurpose::Core;
        let debug = self.purpose == ProcessPurpose::Debug;
        crate::widgets::window(if core {
            "Dump core"
        } else if debug {
            "Attach debugger"
        } else {
            "Attach to process"
        })
            .id(egui::Id::new("attach_process"))
            .open(&mut open)
            .collapsible(false)
            .default_width(width)
            .default_pos(egui::pos2((viewport.width() - width - 16.0) * 0.5, 48.0))
            .max_width((viewport.width() - 64.0).max(200.0))
            .max_height((viewport.height() - 32.0).max(160.0))
            .show(ctx, |ui| {
                if debug {
                    ui.add(egui::Label::new("Attach gdb, IDA, Ghidra or radare2 to a process.").wrap())
                        .on_hover_text("Nothing runs in the guest: the kernel stops and inspects the process without ptrace, so it sees no tracer. The process keeps running until a debugger connects.");
                }
                if core {
                    ui.add(egui::Label::new("Briefly pause this process, capture a native ELF core, then resume.").wrap())
                        .on_hover_text("Its threads are paused too. Resident memory only; unavailable pages remain marked.");
                    let limits = core_context.limits;
                    // Start from the remembered default, and follow a guest that lowers it.
                    if self.core_budget == 0
                        || limits.is_some_and(|limits| u64::from(self.core_budget) > limits.max_size)
                    {
                        self.core_budget = crate::core_budget::initial(limits.as_ref(), core_context.default_mib);
                        self.core_timeout_ms = crate::core_budget::default_timeout_ms(limits.as_ref(), u64::from(self.core_budget));
                    }
                    if let Some(picked) = crate::core_budget::show(
                        ui,
                        "dump-core",
                        &mut self.core_budget,
                        &mut self.core_timeout_ms,
                        limits.as_ref(),
                    ) {
                        self.core_picked = Some(picked);
                    }
                    let (text, warn) = crate::core_budget::caption(limits.as_ref(), core_context.available, u64::from(self.core_budget));
                    let text = RichText::new(text);
                    ui.add(egui::Label::new(if warn { text.color(theme::warn()) } else { text.weak() }).wrap())
                        .on_hover_text("Stored bytes only: untouched mappings cost nothing.");
                }
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
                    if self.pending.is_some() {
                        crate::theme::spinner(ui);
                    }
                    ui.label(if self.pending.is_some() {
                        "Reading processes…".to_owned()
                    } else {
                        page.map_or("Guest processes".into(), |page| {
                            format!("{} guest processes", page.processes.len())
                        })
                    });
                });
                    crate::query::filter_edit(
                        ui,
                        &mut self.filter,
                        "name == sshd",
                        ui.available_width(),
                        crate::query::FilterScope::Table(PROCESS_FIELDS),
                    );
                let filter = crate::query::applied_table(ui, &self.filter, PROCESS_FIELDS, "process-picker");
                if crate::query::compile_table(&self.filter, PROCESS_FIELDS).error.is_none() {
                    crate::query::remember_valid_filter(ui, &self.filter);
                }
                let total = page.map_or(0, |page| page.processes.len());
                let processes: Vec<_> = page.map(|page| page.processes.as_slice()).unwrap_or_default().iter().filter(|process| {
                    use crate::query::RowValue;
                    filter.keep_table(&[
                        ("pid", RowValue::Number(i128::from(process.identity.tgid))),
                        ("name", RowValue::Text(process.command.clone())),
                        ("uid", RowValue::Number(i128::from(process.uid))),
                        ("threads", RowValue::Number(i128::from(process.thread_count))),
                    ])
                }).collect();
                let processes: Vec<_> = crate::table_sort::order(ui.ctx(), "process_picker", processes.len(), |column, a, b| {
                    let (a, b) = (processes[a], processes[b]);
                    match column {
                        0 => a.identity.tgid.cmp(&b.identity.tgid),
                        1 => a.command.to_lowercase().cmp(&b.command.to_lowercase()),
                        2 => a.uid.cmp(&b.uid),
                        _ => a.thread_count.cmp(&b.thread_count),
                    }
                })
                .into_iter()
                .map(|index| processes[index])
                .collect();
                ui.weak(format!("{} / {total} processes in this page", processes.len()));
                if processes.is_empty() && self.pending.is_none() {
                    crate::theme::empty_state(
                        ui,
                        if total == 0 { "No guest processes listed" } else { "No process matches the filter" },
                    );
                }
                if self.selected.as_ref().is_some_and(|selected| !processes.iter().any(|process| &process.identity == selected)) { self.selected = None; }
                // Table body yields space to the selection summary, final actions,
                // its header and horizontal scrollbar at every font size.
                let footer = (font_size + 14.0) * 2.0 + 24.0
                    + if enabled { 0.0 } else { font_size + 12.0 };
                let height = (viewport.bottom() - 32.0 - ui.cursor().top()
                    - (font_size + 12.0) - footer).clamp(32.0, 360.0);
                egui::ScrollArea::horizontal()
                    .id_salt("process_columns")
                    .show(ui, |ui| {
                        ui.set_min_width(440.0_f32.max(font_size * 20.0));
                        crate::widgets::table::begin(ui);
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
                                for (column, label) in ["PID", "Name", "UID", "Threads"].into_iter().enumerate() {
                                    header.col(|ui| {
                                        crate::table_sort::header_aligned(
                                            ui,
                                            "process_picker",
                                            column,
                                            label,
                                            crate::widgets::table::numeric_align(column != 1),
                                        )
                                    });
                                }
                            })
                            .body(|body| {
                                body.rows(font_size + 14.0, processes.len(), |mut row| {
                                    let process = &processes[row.index()];
                                    row.set_selected(
                                        self.selected.as_ref() == Some(&process.identity),
                                    );
                                    for (column, text) in [
                                        process.identity.tgid.to_string(),
                                        process.command.clone(),
                                        process.uid.to_string(),
                                        process.thread_count.to_string(),
                                    ]
                                    .into_iter()
                                    .enumerate()
                                    {
                                        row.col(|ui| {
                                            let label = egui::Label::new(&text)
                                                .selectable(false)
                                                .truncate();
                                            crate::widgets::table::aligned(
                                                ui,
                                                crate::widgets::table::numeric_align(column != 1),
                                                |ui| {
                                                    ui.add(label).on_hover_text(&text);
                                                },
                                            );
                                        });
                                    }
                                    if row.response().clicked() && self.pending.is_none() {
                                        self.selected = Some(process.identity.clone());
                                    }
                                });
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
                    crate::activity::warning(
                        ui,
                        self.unavailable.unwrap_or(if core {
                            "Core capture is not available now."
                        } else if debug {
                            "The debugger is not available now."
                        } else {
                            "Process attachment is not available now."
                        }),
                    );
                }
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            enabled && self.pending.is_none() && selection_current && self.selected.is_some(),
                            egui::Button::new(
                                RichText::new(if core {
                                    format!("{} Dump core", egui_phosphor::regular::FILE)
                                } else if debug {
                                    format!("{} Attach debugger", egui_phosphor::regular::BUG)
                                } else {
                                    format!("{} Attach", egui_phosphor::regular::PLUG)
                                })
                                    .color(theme::palette().primary_text),
                            )
                            .fill(theme::primary()),
                        )
                        .clicked()
                    {
                        if let Some(identity) = self.selected.clone() {
                            action = Some(if core {
                                ProcessAction::DumpCore(identity, self.core_budget, self.core_timeout_ms)
                            } else if debug {
                                ProcessAction::Debug(identity)
                            } else {
                                ProcessAction::Attach(identity)
                            });
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

fn status_color(state: CaptureState) -> egui::Color32 {
    match state {
        CaptureState::Unknown => theme::warn(),
        CaptureState::Active => theme::good(),
        CaptureState::Stopped => theme::info(),
        CaptureState::Finalized => theme::muted(),
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
    let pane_id = ui.id().with("capture-history-focus");
    // Tabs and refresh controls above the list retain their own interactions.
    let pane = ui.interact(
        ui.available_rect_before_wrap(),
        pane_id,
        egui::Sense::click(),
    );
    if pane.clicked() {
        pane.request_focus();
    }
    let fields = capture_fields();
    let filter_id = ui.id().with(("table-filter", "capture-history"));
    let annotations: Vec<_> = captures
        .iter()
        .map(|capture| crate::evidence::annotation(ui, &capture.directory))
        .collect();
    let tags: Vec<_> = annotations
        .iter()
        .flatten()
        .flat_map(|annotation| annotation.tags.iter().cloned())
        .collect();
    let filter =
        crate::query::table_filter(ui, "capture-history", "name contains boot", &fields, &tags);
    let mut shown: Vec<_> = captures
        .iter()
        .filter(|capture| filter.keep_table(&capture_row(ui, capture)))
        .collect();
    shown.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    // Newest first until a header click picks another order.
    let shown: Vec<_> =
        crate::table_sort::order(ui.ctx(), "capture_history", shown.len(), |column, a, b| {
            let (a, b) = (shown[a], shown[b]);
            match column {
                0 => a.started_ms.cmp(&b.started_ms),
                1 => scope(&a.scope)
                    .to_lowercase()
                    .cmp(&scope(&b.scope).to_lowercase()),
                _ => status(a.state).cmp(status(b.state)),
            }
        })
        .into_iter()
        .map(|index| shown[index])
        .collect();
    ui.weak(format!("{} / {} captures", shown.len(), captures.len()));
    let focused = ui.memory(|memory| memory.focused());
    let navigation = if !shown.is_empty() && focused == Some(pane_id) {
        let selected = shown
            .iter()
            .position(|capture| Some(capture.id.as_str()) == selected);
        ui.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Home) {
                Some(0)
            } else if input.consume_key(egui::Modifiers::NONE, egui::Key::End) {
                Some(shown.len() - 1)
            } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                Some(selected.map_or(0, |index| (index + 1).min(shown.len() - 1)))
            } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                Some(selected.map_or(shown.len() - 1, |index| index.saturating_sub(1)))
            } else {
                None
            }
        })
    } else {
        None
    };
    if let Some(index) = navigation {
        action = Some((shown[index].id.clone(), false));
        pane.request_focus();
    }
    let row_height = theme::row_height(font_size);
    let height = (ui.available_height() - row_height).max(row_height * 2.0);
    egui::ScrollArea::horizontal()
        .id_salt("capture_columns")
        .show(ui, |ui| {
            ui.set_min_width(400.0);
            crate::widgets::table::begin(ui);
            let mut table = TableBuilder::new(ui)
                .id_salt("capture_history")
                .column(Column::initial(225.0).at_least(150.0).resizable(true))
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder().at_least(180.0))
                .column(Column::exact(205.0))
                .striped(true)
                .max_scroll_height(height)
                .min_scrolled_height(0.0);
            if let Some(index) = navigation {
                table = table.scroll_to_row(index, Some(egui::Align::Center));
            }
            table
                .header(row_height + 4.0, |mut header| {
                    for (column, label) in
                        ["Start time", "Capture", "State"].into_iter().enumerate()
                    {
                        header.col(|ui| {
                            crate::table_sort::header(ui, "capture_history", column, label)
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, shown.len(), |mut row| {
                        let capture = shown[row.index()];
                        let row_selected = selected == Some(capture.id.as_str());
                        row.set_selected(row_selected);
                        row.col(|ui| {
                            crate::widgets::table::row_mark(
                                ui,
                                if row_selected {
                                    crate::widgets::table::Mark::Selected
                                } else {
                                    crate::widgets::table::Mark::None
                                },
                            );
                            ui.add(
                                egui::Label::new(crate::time_format::unix_ms(capture.started_ms))
                                    .truncate()
                                    .selectable(false)
                                    .sense(egui::Sense::hover()),
                            );
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(crate::evidence::title(
                                    ui,
                                    &capture.directory,
                                    &scope(&capture.scope),
                                ))
                                .selectable(false)
                                .truncate(),
                            )
                            .on_hover_text(&capture.id);
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(
                                    RichText::new(status(capture.state))
                                        .color(status_color(capture.state)),
                                )
                                .selectable(false)
                                .truncate(),
                            )
                            .on_hover_text(status(capture.state));
                        });
                        let response = row.response();
                        if navigation == Some(row.index()) {
                            pane.request_focus();
                        }
                        response.context_menu(|ui| {
                            crate::evidence::menu(ui, &capture.directory);
                            crate::query::table_row_menu(ui, filter_id, &capture_row(ui, capture));
                        });
                        if response.clicked() || response.double_clicked() {
                            pane.request_focus();
                            action = Some((capture.id.clone(), response.double_clicked()));
                        }
                    });
                });
        });
    if captures.is_empty() {
        ui.colored_label(theme::muted(), "No retained captures for this VM");
    }
    action
}

/// Caller uses the applied history query to clear a filtered-out inspector selection.
pub(super) fn matches_capture_filter(ui: &egui::Ui, capture: &CaptureSummary) -> bool {
    let fields = capture_fields();
    let filter_id = ui.id().with(("table-filter", "capture-history"));
    let applied_id = ui.id().with(("applied-table-filter", filter_id));
    let query = ui
        .data(|data| data.get_temp::<String>(applied_id))
        .unwrap_or_default();
    crate::query::compile_table(&query, &fields).keep_table(&capture_row(ui, capture))
}

/// Empties the capture history filter, so every capture is listed again.
pub(super) fn clear_capture_filter(ui: &egui::Ui) {
    let filter_id = ui.id().with(("table-filter", "capture-history"));
    let applied_id = ui.id().with(("applied-table-filter", filter_id));
    ui.data_mut(|data| {
        data.insert_temp(filter_id, String::new());
        data.insert_temp(applied_id, String::new());
    });
}

fn capture_fields() -> Vec<crate::query::FieldSpec<'static>> {
    use crate::query::FieldSpec;
    let mut fields = crate::query::LABEL_FIELDS.to_vec();
    fields.extend(crate::query::CAPTURE_FIELDS);
    fields.extend([
        FieldSpec::text("name", "Displayed capture name"),
        FieldSpec::text("state", "Capture state"),
        FieldSpec::text("scope", "Capture scope"),
        FieldSpec::text("boot", "Guest boot identity"),
        FieldSpec::number("cookie", "Observer cookie"),
        FieldSpec::number("start", "Guest start ns"),
        FieldSpec::number("stop", "Guest stop ns"),
        FieldSpec::number(
            "pid",
            "Observed root process ID; missing for all-userspace capture",
        ),
        FieldSpec::text("error", "Recording error, when present"),
        FieldSpec::text("incomplete", "Recorded incompleteness reason, when present"),
    ]);
    fields
}

fn capture_row(
    ui: &egui::Ui,
    capture: &CaptureSummary,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let annotation = crate::evidence::annotation(ui, &capture.directory);
    let mut row = crate::query::label_row(
        &capture.id,
        annotation.as_ref().map_or("", |value| &value.name),
        &capture.directory.display().to_string(),
        annotation
            .as_ref()
            .map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("capture.kind", RowValue::Text("observer".into())),
        (
            "capture.state",
            RowValue::Text(status(capture.state).into()),
        ),
        (
            "capture.complete",
            RowValue::Bool(
                capture.state == CaptureState::Finalized
                    && capture.incomplete_reason.is_none()
                    && capture.recording_error.is_none(),
            ),
        ),
        (
            "name",
            RowValue::Text(
                annotation
                    .as_ref()
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| scope(&capture.scope), |value| value.name.clone()),
            ),
        ),
        ("state", RowValue::Text(status(capture.state).into())),
        ("entry.kind", RowValue::Text("capture".into())),
        ("entry.state", RowValue::Text(status(capture.state).into())),
        (
            "entry.complete",
            RowValue::Bool(
                capture.state == CaptureState::Finalized
                    && capture.incomplete_reason.is_none()
                    && capture.recording_error.is_none(),
            ),
        ),
        ("vm.id", RowValue::Text(capture.vm_id.clone())),
        ("boot.id", RowValue::Text(capture.boot_id.clone())),
        ("scope", RowValue::Text(scope(&capture.scope))),
        ("boot", RowValue::Text(capture.boot_id.clone())),
        (
            "cookie",
            RowValue::Number(i128::from(capture.capture_cookie)),
        ),
        (
            "start",
            capture.start_ns.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "stop",
            capture.stop_ns.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "pid",
            match &capture.scope {
                CaptureScope::Process { root } => RowValue::Number(i128::from(root.tgid)),
                CaptureScope::AllUserspace => RowValue::Missing,
            },
        ),
        (
            "error",
            capture
                .recording_error
                .as_ref()
                .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
        ),
        (
            "incomplete",
            capture
                .incomplete_reason
                .as_ref()
                .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
        ),
    ]);
    row
}

pub(super) fn detail(ui: &mut egui::Ui, capture: &CaptureSummary) {
    egui::CollapsingHeader::new("Capture details")
        .id_salt("capture_metadata")
        .default_open(false)
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
                crate::activity::warning(ui, warning);
            }
        });
}

/// What a click in the process tree selects.
pub(super) enum ProcessSelection {
    All,
    Process(u32),
}

/// The capture's processes as a tree (parents before children, with guide
/// lines) and their PID, calls and exit status in columns. `None` in
/// `selected` means all processes.
pub(super) fn process_tree(
    ui: &mut egui::Ui,
    processes: &[CaptureProcess],
    selected: Option<u32>,
    font_size: f32,
) -> Option<ProcessSelection> {
    process_tree_tinted(ui, processes, selected, font_size, &|_| None)
}

/// [`process_tree`] with a row tint: `tint` may colour a process's row (and
/// name), as the sample window marks the processes that run library samples.
pub(super) fn process_tree_tinted(
    ui: &mut egui::Ui,
    processes: &[CaptureProcess],
    selected: Option<u32>,
    font_size: f32,
    tint: &dyn Fn(&CaptureProcess) -> Option<egui::Color32>,
) -> Option<ProcessSelection> {
    let mut action = None;
    // Built once per change of the list; a frame only checks the fingerprint.
    let cache_id = ui.id().with("process-tree-layout");
    let layout = match ui.data(|data| data.get_temp::<Arc<layout::Layout>>(cache_id)) {
        Some(layout) if layout.matches(processes) => layout,
        _ => {
            let layout = Arc::new(layout::Layout::build(processes));
            ui.data_mut(|data| data.insert_temp(cache_id, Arc::clone(&layout)));
            layout
        }
    };
    if layout.detached {
        crate::activity::warning(
            ui,
            "PID reuse or incomplete ancestry: cyclic components shown as detached roots",
        );
    }
    ui.horizontal_wrapped(|ui| {
        theme::section(ui, "Processes");
        ui.colored_label(
            theme::muted(),
            format!(
                "{} observed of {}",
                processes.iter().filter(|p| p.packets > 0).count(),
                processes.len()
            ),
        );
        if ui
            .selectable_label(selected.is_none(), "All processes")
            .clicked()
        {
            action = Some(ProcessSelection::All);
        }
    });
    let mono = theme::mono(font_size - 1.0);
    let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
    let row_height = theme::row_height(font_size);
    // The number columns have fixed widths; the process column is as wide as
    // its longest row, or the panel if that is wider, and the tree scrolls
    // sideways when it is not.
    let numbers = char_width * 30.0 + 24.0 + 3.0 * ui.spacing().item_spacing.x;
    let rows = layout.rows.iter().map(|row| {
        let process = &processes[row.process as usize];
        let exe = process
            .exe
            .as_deref()
            .map_or(0, |exe| exe.chars().count() + 2);
        let chars =
            row.depth as usize * crate::tree_lines::CELL_CHARS + process.name.chars().count() + exe;
        chars as f32 * char_width + 12.0
    });
    let wanted = rows.fold(160.0_f32, f32::max);
    let process_width = wanted.max(ui.available_width() - numbers - 16.0);
    egui::ScrollArea::horizontal()
        .id_salt("capture_process_tree_columns")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            crate::widgets::table::begin(ui);
            TableBuilder::new(ui)
                .id_salt("capture_process_tree")
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .auto_shrink([false, false])
                .max_scroll_height(f32::INFINITY)
                .min_scrolled_height(0.0)
                .column(Column::exact(process_width).clip(true))
                .column(Column::exact(char_width * 8.0 + 8.0))
                .column(Column::exact(char_width * 10.0 + 8.0))
                .column(Column::exact(char_width * 12.0 + 8.0))
                .header(row_height + 4.0, |mut header| {
                    for label in ["Process", "PID", "Calls", "Exit"] {
                        header.col(|ui| crate::widgets::table::head(ui, label));
                    }
                })
                .body(|body| {
                    body.rows(row_height, layout.rows.len(), |mut row| {
                        let process = &processes[layout.rows[row.index()].process as usize];
                        let branch = layout.prefix(row.index());
                        let row_selected = selected == Some(process.pid);
                        row.set_selected(row_selected);
                        let tinted = tint(process);
                        let wash = |ui: &mut egui::Ui| {
                            if let Some(color) = tinted {
                                let spacing = ui.spacing().item_spacing;
                                ui.painter().rect_filled(
                                    ui.max_rect()
                                        .expand2(egui::vec2(spacing.x / 2.0, spacing.y / 2.0)),
                                    0.0,
                                    color.gamma_multiply(0.18),
                                );
                            }
                        };
                        row.col(|ui| {
                            wash(ui);
                            crate::widgets::table::row_mark(
                                ui,
                                if row_selected {
                                    crate::widgets::table::Mark::Selected
                                } else {
                                    crate::widgets::table::Mark::None
                                },
                            );
                            let reach = ui.spacing().item_spacing.y * 0.5;
                            let lines = ui.max_rect().expand2(egui::vec2(0.0, reach));
                            branch.paint(ui.painter(), lines, char_width);
                            ui.add_space(branch.width(char_width) + 4.0);
                            let name = if process.name.is_empty() {
                                "?"
                            } else {
                                process.name.as_str()
                            };
                            let color = if let Some(color) = tinted {
                                color
                            } else if process.packets == 0 {
                                theme::muted()
                            } else {
                                theme::value(theme::ValueKind::Name)
                            };
                            ui.add(
                                egui::Label::new(RichText::new(name).color(color))
                                    .selectable(false)
                                    .truncate(),
                            );
                            if let Some(exe) = process.exe.as_deref().filter(|exe| {
                                std::path::Path::new(exe)
                                    .file_name()
                                    .is_none_or(|file| file.to_string_lossy() != name)
                            }) {
                                ui.add_space(6.0);
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(exe).font(mono.clone()).color(theme::muted()),
                                    )
                                    .selectable(false)
                                    .truncate(),
                                );
                            }
                        });
                        row.col(|ui| {
                            wash(ui);
                            ui.label(
                                RichText::new(process.pid.to_string())
                                    .font(mono.clone())
                                    .color(theme::value(theme::ValueKind::Number)),
                            );
                        });
                        row.col(|ui| {
                            wash(ui);
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if process.calls > 0 {
                                        ui.label(
                                            RichText::new(process.calls.to_string())
                                                .font(mono.clone())
                                                .color(theme::text()),
                                        );
                                    } else {
                                        ui.label(
                                            RichText::new("-")
                                                .font(mono.clone())
                                                .color(theme::muted()),
                                        );
                                    }
                                },
                            );
                        });
                        row.col(|ui| {
                            wash(ui);
                            ui.add_space(8.0);
                            let (text, color) = exit_status(process);
                            ui.label(RichText::new(text).font(mono.clone()).color(color));
                        });
                        let response = row.response().on_hover_text(process_hover(process));
                        if response.clicked() {
                            action = Some(ProcessSelection::Process(process.pid));
                        }
                    });
                });
        });
    action
}

/// Exit status text and color: 0 is good, another code or a signal an
/// error. The kernel reports a wait status: `exit(1)` is 256, SIGKILL 9.
fn exit_status(process: &CaptureProcess) -> (String, egui::Color32) {
    let status = process
        .exit_code
        .and_then(|raw| WaitStatus::from_raw(u64::try_from(raw).ok()?));
    match (process.exited, status) {
        (true, Some(status @ WaitStatus::Exited { code: 0 })) => {
            (values::task_end(&status), theme::good())
        }
        (true, Some(status)) => (values::task_end(&status), theme::error()),
        (true, None) => ("exited".into(), theme::warn()),
        (false, _) => (String::new(), theme::muted()),
    }
}

/// Processes in tree order (parents before children) with their depth; a
/// cycle (reused PIDs) ends at a process already listed.
fn tree_rows(processes: &[CaptureProcess]) -> Vec<(&CaptureProcess, usize)> {
    layout::Layout::build(processes)
        .rows
        .iter()
        .map(|row| (&processes[row.process as usize], row.depth as usize))
        .collect()
}

fn process_label(process: &CaptureProcess) -> String {
    let name = if process.name.is_empty() {
        "?"
    } else {
        process.name.as_str()
    };
    format!("{name} ({})", process.pid)
}

/// The trace header's process picker for a capture.
pub(super) fn process_menu(
    ui: &mut egui::Ui,
    processes: &[CaptureProcess],
    selected: Option<u32>,
) -> Option<ProcessSelection> {
    let mut action = None;
    let current = selected
        .and_then(|pid| processes.iter().find(|p| p.pid == pid))
        .map_or_else(|| "All processes".to_owned(), process_label);
    egui::ComboBox::from_id_salt("trace_process")
        .selected_text(current)
        .width(220.0)
        .height(480.0)
        .show_ui(ui, |ui| {
            if ui
                .selectable_label(selected.is_none(), "All processes")
                .clicked()
            {
                action = Some(ProcessSelection::All);
            }
            let rows = tree_rows(processes);
            let depths: Vec<_> = rows.iter().map(|(_, depth)| *depth).collect();
            let font = egui::TextStyle::Monospace.resolve(ui.style());
            let body = egui::TextStyle::Body.resolve(ui.style());
            for ((process, _), branch) in rows.iter().zip(crate::tree_lines::prefixes(&depths)) {
                let mut text = branch.job(&font);
                text.append(
                    &process_label(process),
                    0.0,
                    egui::TextFormat::simple(body.clone(), theme::text()),
                );
                if ui
                    .selectable_label(selected == Some(process.pid), text)
                    .on_hover_text(process_hover(process))
                    .clicked()
                {
                    action = Some(ProcessSelection::Process(process.pid));
                }
            }
        });
    action
}

fn process_hover(process: &CaptureProcess) -> String {
    let mut lines = vec![format!("PID {}", process.pid)];
    if process.parent_pid != 0 {
        lines.push(format!("Parent PID {}", process.parent_pid));
    }
    if let Some(exe) = &process.exe {
        lines.push(format!("Executed {exe}"));
    }
    lines.push(if process.at_start {
        "Running when the capture started".into()
    } else {
        "Started during the capture".into()
    });
    lines.push(format!(
        "{} system calls, {} packets",
        process.calls, process.packets
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_keyboard_selects_rows_without_intercepting_text_editor_navigation() {
        let ctx = egui::Context::default();
        let captures: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| CaptureSummary {
                started_ms: Some(if id == "first" { 100 } else { 200 }),
                id: id.into(),
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                capture_cookie: 1,
                scope: CaptureScope::AllUserspace,
                directory: std::path::PathBuf::from(format!("/nonexistent-capture-keyboard/{id}")),
                state: CaptureState::Finalized,
                recording_error: None,
                start_ns: None,
                stop_ns: None,
                incomplete_reason: None,
            })
            .collect();
        let mut text = String::new();
        let mut selected = Some("first".to_owned());
        let mut actual = None;
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                history(ui, &captures, selected.as_deref(), 16.0);
                ui.memory_mut(|memory| memory.request_focus(ui.id().with("capture-history-focus")));
            });
        });
        for (key, expected) in [
            (egui::Key::End, "first"),
            (egui::Key::ArrowUp, "second"),
            (egui::Key::ArrowDown, "first"),
            (egui::Key::Home, "second"),
        ] {
            let input = egui::RawInput {
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    actual = history(ui, &captures, selected.as_deref(), 16.0);
                });
            });
            assert_eq!(
                actual.as_ref().map(|(id, opened)| (id.as_str(), *opened)),
                Some((expected, false))
            );
            selected = actual.take().map(|(id, _)| id);
        }
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                history(ui, &captures, selected.as_deref(), 16.0);
                ui.add(egui::TextEdit::singleline(&mut text))
                    .request_focus();
            });
        });
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key: egui::Key::End,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    actual = history(ui, &captures, selected.as_deref(), 16.0);
                    ui.add(egui::TextEdit::singleline(&mut text));
                });
            },
        );
        assert!(actual.is_none());
    }

    #[test]
    fn capture_selection_uses_last_valid_filter_and_available_identity_fields() {
        let ctx = egui::Context::default();
        let capture = CaptureSummary {
            started_ms: None,
            id: "filter-capture".into(),
            vm_id: "vm-one".into(),
            boot_id: "boot-one".into(),
            capture_cookie: u64::MAX,
            scope: CaptureScope::Process {
                root: GuestProcessIdentity {
                    boot_id: "boot-one".into(),
                    task_cookie: 9,
                    tgid: 42,
                    start_boot_ns: 0,
                },
            },
            directory: std::path::PathBuf::from("/nonexistent-antinomie-filter-fixture"),
            state: CaptureState::Active,
            recording_error: None,
            start_ns: Some(0),
            stop_ns: None,
            incomplete_reason: None,
        };
        for (draft, expected) in [
            ("vm.id == \"vm-one\" && pid == 42 && cookie == 18446744073709551615 && start == 0 && missing(stop)", true),
            ("pid == 41", false),
            ("pid ==", false),
            ("", true),
        ] {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let id = ui.id().with(("table-filter", "capture-history"));
                    let filter = crate::query::applied_table(ui, draft, &capture_fields(), id);
                    assert_eq!(filter.keep_table(&capture_row(ui, &capture)), expected);
                    assert_eq!(matches_capture_filter(ui, &capture), expected);
                });
            });
        }
    }

    #[test]
    fn reused_pid_cycle_keeps_all_observed_processes_visible() {
        let processes = vec![
            CaptureProcess {
                pid: 100,
                parent_pid: 200,
                ..Default::default()
            },
            CaptureProcess {
                pid: 200,
                parent_pid: 100,
                ..Default::default()
            },
            CaptureProcess {
                pid: 300,
                parent_pid: 200,
                ..Default::default()
            },
        ];
        let rows = tree_rows(&processes);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].1, 0);
        assert_eq!(
            rows.iter()
                .map(|(process, _)| process.pid)
                .collect::<std::collections::BTreeSet<_>>(),
            [100, 200, 300].into()
        );
    }

    fn process(pid: u32, parent_pid: u32) -> CaptureProcess {
        CaptureProcess {
            pid,
            parent_pid,
            name: format!("p{pid}"),
            ..CaptureProcess::default()
        }
    }

    #[test]
    fn process_branches_follow_the_tree_order() {
        // 1
        // ├── 2
        // │   └── 4
        // └── 3
        //     └── 5
        let processes = [
            process(1, 0),
            process(2, 1),
            process(3, 1),
            process(4, 2),
            process(5, 3),
        ];
        let rows = tree_rows(&processes);
        let order: Vec<_> = rows.iter().map(|(p, depth)| (p.pid, *depth)).collect();
        assert_eq!(order, [(1, 0), (2, 1), (4, 2), (3, 1), (5, 2)]);
        let depths: Vec<_> = rows.iter().map(|(_, depth)| *depth).collect();
        let branches: Vec<_> = crate::tree_lines::prefixes(&depths)
            .iter()
            .map(crate::tree_lines::Prefix::text)
            .collect();
        assert_eq!(branches, ["", "├── ", "│   └── ", "└── ", "    └── "]);
    }

    #[test]
    fn exit_status_colors_follow_the_wait_status() {
        let mut failed = process(9, 1);
        failed.exited = true;
        failed.exit_code = Some(2 << 8);
        assert_eq!(exit_status(&failed), ("exit 2".into(), theme::error()));
        failed.exit_code = Some(9);
        assert_eq!(exit_status(&failed).0, "killed by SIGKILL");
        failed.exit_code = Some(0);
        assert_eq!(exit_status(&failed).1, theme::good());
    }
}
