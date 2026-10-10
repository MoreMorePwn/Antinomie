//! Native process selection and observer history, without program terminals.
use super::{icon, theme};
use antinomie_monitor_core::{
    capture_processes::CaptureProcess, CaptureScope, CaptureState, CaptureSummary,
    GuestProcessIdentity, GuestProcessPage,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

#[derive(Default)]
pub(super) struct ProcessPicker {
    pub open: bool,
    pub after_pid: u32,
    pub selected: Option<GuestProcessIdentity>,
    pub pending: Option<u64>,
    /// Name or PID text the list is narrowed to.
    pub filter: String,
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
                    ui.label(if self.pending.is_some() {
                        "Reading processes...".to_owned()
                    } else {
                        page.map_or("Guest processes".into(), |page| {
                            format!("{} guest processes", page.processes.len())
                        })
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .desired_width(160.0)
                            .hint_text("Filter by name or PID"),
                    );
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
                                let needle = self.filter.trim().to_lowercase();
                                let processes: Vec<_> = page
                                    .map(|page| page.processes.as_slice())
                                    .unwrap_or_default()
                                    .iter()
                                    .filter(|process| {
                                        needle.is_empty()
                                            || process.command.to_lowercase().contains(&needle)
                                            || process
                                                .identity
                                                .tgid
                                                .to_string()
                                                .starts_with(&needle)
                                    })
                                    .collect();
                                body.rows(font_size + 14.0, processes.len(), |mut row| {
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
                    ui.colored_label(theme::warn(), "Process attachment unavailable");
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
    // The list takes the rows it needs, up to 40% of the height, so the
    // process tree below gets the rest.
    let row_height = theme::row_height(font_size);
    let height = (captures.len().max(2) as f32 * row_height)
        .min(ui.available_height() * 0.4)
        .max(row_height * 2.0);
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
                .header(row_height + 4.0, |mut header| {
                    for label in ["Capture", "State"] {
                        header.col(|ui| {
                            theme::section(ui, label);
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, captures.len(), |mut row| {
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
                        if response.clicked() || response.double_clicked() {
                            action = Some((capture.id.clone(), response.double_clicked()));
                        }
                    });
                });
        });
    ui.separator();
    if let Some(capture) = selected.and_then(|id| captures.iter().find(|capture| capture.id == id))
    {
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
                    ui.label(RichText::new(warning).color(theme::warn()));
                }
            });
    } else if captures.is_empty() {
        ui.colored_label(theme::muted(), "No retained captures for this VM");
    }
    action
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
    let mut action = None;
    let rows = tree_rows(processes);
    let guides = tree_guides(&rows);
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
    let indent = 18.0;
    TableBuilder::new(ui)
        .id_salt("capture_process_tree")
        .sense(egui::Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .striped(true)
        .auto_shrink([false, false])
        .max_scroll_height(f32::INFINITY)
        .min_scrolled_height(0.0)
        .column(Column::remainder().at_least(160.0).clip(true))
        .column(Column::exact(char_width * 8.0 + 8.0))
        .column(Column::exact(char_width * 10.0 + 8.0))
        .column(Column::exact(char_width * 12.0 + 8.0))
        .header(row_height + 4.0, |mut header| {
            for label in ["Process", "PID", "Calls", "Exit"] {
                header.col(|ui| {
                    theme::section(ui, label);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let (process, depth) = rows[row.index()];
                let continues = &guides[row.index()];
                row.set_selected(selected == Some(process.pid));
                row.col(|ui| {
                    let rect = ui.max_rect();
                    let stroke = egui::Stroke::new(1.0_f32, theme::muted().gamma_multiply(0.6));
                    let painter = ui.painter();
                    for level in 1..=depth {
                        let x = rect.left() + (level - 1) as f32 * indent + indent * 0.5;
                        let below = continues[level - 1];
                        if level < depth {
                            if below {
                                painter.vline(x, rect.y_range(), stroke);
                            }
                        } else {
                            let bottom = if below {
                                rect.bottom()
                            } else {
                                rect.center().y
                            };
                            painter.vline(x, rect.top()..=bottom, stroke);
                            painter.hline(x..=x + indent * 0.5, rect.center().y, stroke);
                        }
                    }
                    ui.add_space(depth as f32 * indent + 4.0);
                    let name = if process.name.is_empty() {
                        "?"
                    } else {
                        process.name.as_str()
                    };
                    let color = if process.packets == 0 {
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
                    ui.label(
                        RichText::new(process.pid.to_string())
                            .font(mono.clone())
                            .color(theme::value(theme::ValueKind::Number)),
                    );
                });
                row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if process.calls > 0 {
                            ui.label(
                                RichText::new(process.calls.to_string())
                                    .font(mono.clone())
                                    .color(theme::text()),
                            );
                        } else {
                            ui.label(RichText::new("-").font(mono.clone()).color(theme::muted()));
                        }
                    });
                });
                row.col(|ui| {
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
    action
}

/// Exit status text and color: 0 is good, another code an error.
fn exit_status(process: &CaptureProcess) -> (String, egui::Color32) {
    match (process.exited, process.exit_code) {
        (true, Some(0)) => ("exit 0".into(), theme::good()),
        (true, Some(code)) => (format!("exit {code}"), theme::error()),
        (true, None) => ("exited".into(), theme::warn()),
        (false, _) => (String::new(), theme::muted()),
    }
}

/// For each row of `tree_rows`, whether each of its levels (1..=depth)
/// continues below it: a later sibling of the row (last level) or of its
/// ancestor at that level, so the guide line goes on down.
fn tree_guides(rows: &[(&CaptureProcess, usize)]) -> Vec<Vec<bool>> {
    let mut guides = vec![Vec::new(); rows.len()];
    // Walking up from the bottom: whether a row at each depth was seen
    // since the last shallower one.
    let mut seen: Vec<bool> = Vec::new();
    for (index, (_, depth)) in rows.iter().enumerate().rev() {
        let depth = *depth;
        if seen.len() <= depth {
            seen.resize(depth + 1, false);
        }
        guides[index] = (1..=depth).map(|level| seen[level]).collect();
        seen[depth] = true;
        for deeper in seen.iter_mut().skip(depth + 1) {
            *deeper = false;
        }
    }
    guides
}

/// Processes in tree order (parents before children) with their depth; a
/// cycle (reused PIDs) ends at a process already listed.
fn tree_rows(processes: &[CaptureProcess]) -> Vec<(&CaptureProcess, usize)> {
    let known: std::collections::BTreeSet<u32> = processes.iter().map(|p| p.pid).collect();
    let mut children: std::collections::BTreeMap<u32, Vec<&CaptureProcess>> =
        std::collections::BTreeMap::new();
    let mut roots = Vec::new();
    for process in processes {
        if process.parent_pid != 0
            && process.parent_pid != process.pid
            && known.contains(&process.parent_pid)
        {
            children
                .entry(process.parent_pid)
                .or_default()
                .push(process);
        } else {
            roots.push(process);
        }
    }
    let mut rows = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    let mut stack: Vec<(&CaptureProcess, usize)> = roots.iter().rev().map(|p| (*p, 0)).collect();
    while let Some((process, depth)) = stack.pop() {
        if !visited.insert(process.pid) {
            continue;
        }
        rows.push((process, depth));
        if let Some(kids) = children.get(&process.pid) {
            stack.extend(kids.iter().rev().map(|kid| (*kid, depth + 1)));
        }
    }
    rows
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
            for (process, depth) in tree_rows(processes) {
                let text = format!("{}{}", "  ".repeat(depth), process_label(process));
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

    fn process(pid: u32, parent_pid: u32) -> CaptureProcess {
        CaptureProcess {
            pid,
            parent_pid,
            name: format!("p{pid}"),
            ..CaptureProcess::default()
        }
    }

    #[test]
    fn tree_guides_continue_only_to_later_siblings() {
        // 1
        // ├ 2
        // │ └ 4
        // └ 3
        //   └ 5
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
        assert_eq!(
            tree_guides(&rows),
            [
                vec![],
                vec![true],
                vec![true, false],
                vec![false],
                vec![false, false],
            ]
        );
        let mut failed = process(9, 1);
        failed.exited = true;
        failed.exit_code = Some(2);
        assert_eq!(exit_status(&failed), ("exit 2".into(), theme::error()));
        failed.exit_code = Some(0);
        assert_eq!(exit_status(&failed).1, theme::good());
    }
}
