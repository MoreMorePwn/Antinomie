//! Opt-in launch selection and retained, run-addressed analysis evidence.
use antinomie_monitor_core::{
    analysis_tools::ToolStatus, AnalysisExportFormat, AnalysisKind, AnalysisReport,
    AnalysisSectionState, AnalysisSelection, AnalysisState, ExecRequest, RunIn,
};
use eframe::egui;
mod entropy;
mod listing_view;
mod meaning;
mod records;
mod row_menu;
mod source;
mod workspace;
pub(crate) use listing_view::{export_ghidra_text, index_ghidra_markers};
pub(crate) use listing_view::{listing_fields, listing_row_with};
#[cfg(test)]
pub(crate) use source::ARGUMENT_PLACEHOLDER;
pub(crate) use source::{LaunchSource, ProgramSource, SourceOutcome, UploadFields};
pub(crate) use workspace::{details, workspace, workspace_section, WorkspaceState};

#[derive(Clone, Copy)]
pub(crate) struct LaunchCapabilities {
    pub graphical: bool,
    pub core_on_exit: bool,
    pub debug_on_start: bool,
    /// What the guest accepts for process cores, once it has said.
    pub core_limits: Option<antinomie_monitor_core::CoreLimits>,
    /// The remembered default budget, MiB.
    pub core_default_mib: u32,
}

/// Where the Run form leaves the budget the user picked, for the caller to remember.
pub(crate) fn remembered_budget_id() -> egui::Id {
    egui::Id::new("remembered-core-budget")
}

/// What the Run form asks for besides editing its fields.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LaunchOutcome {
    /// The user asked to install a missing analysis tool.
    pub install: bool,
    pub source: SourceOutcome,
}

/// Program fields and the analysis selection. `capabilities.graphical`
/// offers the Run in choice, which only a graphical base's session can use.
pub(crate) fn launch_fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    tools: &[ToolStatus],
    capabilities: LaunchCapabilities,
    source: ProgramSource<'_>,
) -> LaunchOutcome {
    let mut outcome = LaunchOutcome::default();
    let spacing = ui.spacing().item_spacing.x;
    let min_pane = ui.text_style_height(&egui::TextStyle::Body) * 22.0;
    if ui.available_width() >= min_pane * 2.0 + spacing {
        ui.columns(2, |columns| {
            outcome.source = fields(
                &mut columns[0],
                request,
                args,
                env,
                capabilities.graphical,
                source,
            );
            crate::theme::section(&mut columns[1], "Analysis");
            selection(
                &mut columns[1],
                &mut request.analysis,
                tools,
                &mut outcome.install,
            );
            capture_selection(&mut columns[1], request, capabilities);
            debugger_selection(&mut columns[1], request, capabilities.debug_on_start);
        });
    } else {
        outcome.source = fields(ui, request, args, env, capabilities.graphical, source);
        ui.add_space(6.0);
        crate::theme::section(ui, "Analysis");
        selection(ui, &mut request.analysis, tools, &mut outcome.install);
        capture_selection(ui, request, capabilities);
        debugger_selection(ui, request, capabilities.debug_on_start);
    }
    outcome
}

fn capture_selection(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    capabilities: LaunchCapabilities,
) {
    let core_supported = capabilities.core_on_exit;
    ui.add_space(12.0);
    crate::theme::section(ui, "Memory");
    ui.checkbox(&mut request.memory_dump_on_exit, "Memory Dump on Exit")
        .on_hover_text("Dump VM RAM after the process tree exits. This is post-exit VM memory, not a process core.");
    let core_enabled = core_supported && request.run_in == RunIn::AppTerminal;
    if !core_enabled {
        request.core_dump_on_exit = false;
    }
    ui.add_enabled(
        core_enabled,
        egui::Checkbox::new(&mut request.core_dump_on_exit, "Core Dump on Exit"),
    )
    .on_hover_text("Capture the launched root process before exit, including thread registers and selected memory. Linux x86-64; memory is filtered and bounded by the budget below, so captures may be partial. Some fatal exits, including SIGKILL, may leave register context unavailable. Thread synchronization and page faults may delay exit.")
    .on_disabled_hover_text(core_unavailable_reason(core_supported));
    if core_enabled && request.core_dump_on_exit {
        core_budget_row(ui, request, capabilities);
    } else {
        request.core_max_size = None;
        request.core_timeout_ms = None;
    }
    if !core_enabled {
        ui.add(
            egui::Label::new(egui::RichText::new(core_unavailable_reason(core_supported)).weak())
                .wrap(),
        );
    }
    ui.add_space(12.0);
    crate::theme::section(ui, "Network");
    ui.checkbox(&mut request.capture_network, "Capture network from start until tree exits")
        .on_hover_text("Record VM network packets during this run. Packets are VM-wide, not attributed to this process.");
}

/// Budget and deadline of the exit core, with what the guest accepts.
fn core_budget_row(ui: &mut egui::Ui, request: &mut ExecRequest, capabilities: LaunchCapabilities) {
    let limits = capabilities.core_limits;
    let mut budget = request.core_max_size.unwrap_or_else(|| {
        crate::core_budget::initial(limits.as_ref(), capabilities.core_default_mib)
    });
    let mut timeout = request.core_timeout_ms.unwrap_or_else(|| {
        crate::core_budget::default_timeout_ms(limits.as_ref(), u64::from(budget))
    });
    if let Some(limits) = limits.as_ref()
        && u64::from(budget) > limits.max_size
    {
        budget = limits.effective_budget(budget >> 20);
        timeout = crate::core_budget::default_timeout_ms(Some(limits), u64::from(budget));
    }
    ui.indent("core-budget", |ui| {
        if let Some(picked) =
            crate::core_budget::show(ui, "run-core", &mut budget, &mut timeout, limits.as_ref())
        {
            ui.data_mut(|data| data.insert_temp(remembered_budget_id(), picked));
        }
        let (text, warn) = crate::core_budget::caption(limits.as_ref(), None, u64::from(budget));
        let text = egui::RichText::new(text);
        ui.add(
            egui::Label::new(if warn {
                text.color(crate::theme::warn())
            } else {
                text.weak()
            })
            .wrap(),
        );
    });
    // Until the guest has said what it accepts, the request keeps the contract
    // every guest has: 64 MiB and 5 s.
    if limits.is_some() {
        request.core_max_size = Some(budget);
        request.core_timeout_ms = Some(timeout);
    }
}

fn debugger_selection(ui: &mut egui::Ui, request: &mut ExecRequest, supported: bool) {
    ui.add_space(12.0);
    crate::theme::section(ui, "Debugger");
    let enabled = supported && request.run_in == RunIn::AppTerminal;
    if !enabled {
        request.debug_on_start = false;
    }
    let reason = if supported {
        "Debug on start requires Run in: App terminal."
    } else {
        "Debug on start requires a base built for Antinomie 0.7.0."
    };
    ui.add_enabled(
        enabled,
        egui::Checkbox::new(&mut request.debug_on_start, "Debug on start"),
    )
    .on_hover_text("Stop the program before its first instruction (the loader's, for a dynamic program) and open the debugger on it. The run shows the gdb command to attach with; the program waits until a debugger continues it. Nothing runs in the guest for this.")
    .on_disabled_hover_text(reason);
    if !enabled {
        ui.add(egui::Label::new(egui::RichText::new(reason).weak()).wrap());
    }
}

fn core_unavailable_reason(core_supported: bool) -> &'static str {
    if core_supported {
        "Core capture requires Run in: App terminal; desktop launchers run a shell wrapper."
    } else {
        "Core capture requires a guest built with revision 15 or newer."
    }
}

fn fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    graphical: bool,
    source: ProgramSource<'_>,
) -> SourceOutcome {
    crate::theme::section(ui, "Program");
    let label_width = ui.text_style_height(&egui::TextStyle::Body) * 8.5;
    let mut outcome = SourceOutcome::default();
    egui::Grid::new("run-program-fields")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .min_col_width(label_width)
        .show(ui, |ui| {
            outcome = source::rows(ui, &mut request.path, source);
            for (label, value, rows, hint) in [
                ("Arguments", &mut *args, 4, source::ARGUMENT_PLACEHOLDER),
                ("Working directory", &mut request.cwd, 1, "/"),
                ("Environment", &mut *env, 3, "One NAME=value entry per line"),
            ] {
                let label_response = ui.label(label);
                let edit = if rows > 1 {
                    egui::TextEdit::multiline(value).desired_rows(rows)
                } else {
                    egui::TextEdit::singleline(value)
                };
                ui.add(
                    edit.margin(crate::theme::TEXT_EDIT_MARGIN)
                        .font(egui::TextStyle::Monospace)
                        .hint_text(crate::theme::hint_text(hint))
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label_response.id);
                ui.end_row();
            }
            ui.label("User");
            identity_fields(ui, request);
            ui.end_row();
        });
    if graphical {
        ui.add_space(6.0);
        crate::theme::section(ui, "Session");
        run_in(ui, &mut request.run_in, request.uid);
    }
    outcome
}

fn identity_fields(ui: &mut egui::Ui, request: &mut ExecRequest) {
    ui.horizontal_wrapped(|ui| {
        let selected = match (request.uid, request.gid) {
            (0, 0) => "Root",
            (1000, 1000) => "Normal user",
            _ => "Custom",
        };
        egui::ComboBox::from_id_salt("launch-user-preset")
            .selected_text(selected)
            .show_ui(ui, |ui| {
                for (label, id) in [("Root", 0), ("Normal user", 1000)] {
                    if ui
                        .selectable_label(request.uid == id && request.gid == id, label)
                        .on_hover_text(format!("UID {id}, GID {id}"))
                        .clicked()
                    {
                        (request.uid, request.gid) = (id, id);
                    }
                }
            });
        // UID and GID stay together: when the pair does not fit beside the
        // preset, it moves to the next line as a whole, never the GID alone.
        // Its width is what it measured last frame.
        let pair_id = ui.id().with("uid-gid-width");
        let pair = ui
            .data(|data| data.get_temp::<f32>(pair_id))
            .unwrap_or(200.0);
        let room = ui.max_rect().right() - ui.next_widget_position().x;
        if room < pair + ui.spacing().item_spacing.x {
            ui.end_row();
        }
        let mut width = 3.0 * ui.spacing().item_spacing.x;
        width += ui
            .label(egui::RichText::new("UID").color(crate::theme::muted()))
            .rect
            .width();
        width += ui
            .add(egui::DragValue::new(&mut request.uid).range(0..=u32::MAX))
            .rect
            .width();
        width += ui
            .label(egui::RichText::new("GID").color(crate::theme::muted()))
            .rect
            .width();
        width += ui
            .add(egui::DragValue::new(&mut request.gid).range(0..=u32::MAX))
            .rect
            .width();
        if ui.data(|data| data.get_temp::<f32>(pair_id)) != Some(width) {
            ui.data_mut(|data| data.insert_temp(pair_id, width));
            ui.ctx().request_repaint();
        }
    });
}

/// Where the program runs: this app's terminal or the guest's desktop.
fn run_in(ui: &mut egui::Ui, choice: &mut RunIn, uid: u32) {
    ui.horizontal_wrapped(|ui| {
        let label = ui.label("Run in");
        egui::ComboBox::from_id_salt("run-in")
            .selected_text(choice.label())
            .show_ui(ui, |ui| {
                for option in RunIn::ALL {
                    ui.selectable_value(choice, option, option.label())
                        .on_hover_text(option.description());
                }
            })
            .response
            .labelled_by(label.id);
    });
    ui.colored_label(crate::theme::muted(), choice.description());
    if choice.guest_desktop() {
        ui.colored_label(
            crate::theme::muted(),
            if uid == 0 {
                "Log in on the VM display as a normal user first; a root run joins that user's desktop. The run also records the launch script."
            } else {
                "Log in on the VM display as this UID first. The run also records the launch script that joins the session."
            },
        );
    }
    if *choice == RunIn::GuestDesktopTerminal {
        ui.colored_label(
            crate::theme::muted(),
            "The desktop's own terminal is started for this run, so the program stays in it. A guest with only another x-terminal-emulator may run the program outside the run; Capture All still records it.",
        );
    }
}

pub(crate) fn selection(
    ui: &mut egui::Ui,
    selection: &mut AnalysisSelection,
    tools: &[ToolStatus],
    install: &mut bool,
) -> egui::Response {
    use crate::tree_lines::{self, Prefix};
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let char_width = tree_lines::char_width(ui, &mono);
    let root = Prefix::default();
    let mut state = egui::collapsing_header::CollapsingState::load_with_default_open(
        ui.ctx(),
        ui.make_persistent_id("analysis-tree"),
        true,
    );
    let master = tree_lines::row(ui, &root, char_width, |ui| {
        tree_lines::caret(ui, &mut state);
        ui.checkbox(&mut selection.enabled, "Static Analysis")
            .on_hover_text("Analyze the initial executable only")
    });
    if state.is_open() {
        ui.add_enabled_ui(selection.enabled, |ui| {
            let groups = [
                ("Triage", AnalysisKind::TRIAGE),
                ("Deep analysis", AnalysisKind::DEEP),
            ];
            for (index, (label, kinds)) in groups.into_iter().enumerate() {
                let branch = root.child(index + 1 == groups.len());
                let mut group = egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    ui.make_persistent_id(("analysis-branch", label)),
                    true,
                );
                let mut open = group.is_open();
                tree_lines::row(ui, &branch, char_width, |ui| {
                    open = tree_lines::caret(ui, &mut group);
                    let name = ui
                        .add(
                            egui::Label::new(label)
                                .selectable(false)
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if name.clicked() {
                        open = !open;
                        group.set_open(open);
                        group.store(ui.ctx());
                    }
                });
                if !open {
                    continue;
                }
                for (position, &kind) in kinds.iter().enumerate() {
                    let leaf = branch.child(position + 1 == kinds.len());
                    tree_lines::row(ui, &leaf, char_width, |ui| check(ui, selection, kind));
                    needs_tool(ui, &leaf, char_width, selection, kind, tools, install);
                }
            }
        });
    }
    if let Err(reason) = selection.validate() {
        crate::activity::error(ui, reason);
    }
    master.inner
}

/// Under a selected category whose tool is missing: what it needs and a way
/// to install it.
fn needs_tool(
    ui: &mut egui::Ui,
    parent: &crate::tree_lines::Prefix,
    char_width: f32,
    selection: &AnalysisSelection,
    kind: AnalysisKind,
    tools: &[ToolStatus],
    install: &mut bool,
) {
    let (id, name) = match kind {
        AnalysisKind::Capabilities => ("capa", "capa"),
        AnalysisKind::Floss => ("floss", "FLOSS"),
        AnalysisKind::Unpacking => ("upx", "UPX"),
        AnalysisKind::Decompilation => ("ghidra", "Ghidra"),
        _ => return,
    };
    if !selection.checks.contains(&kind)
        || tools
            .iter()
            .find(|tool| tool.id == id)
            .is_none_or(ToolStatus::available)
    {
        return;
    }
    crate::tree_lines::row(ui, &parent.child(true), char_width, |ui| {
        crate::activity::warning(ui, format!("Needs {name}, not installed"));
        if ui.small_button("Install…").clicked() {
            *install = true;
        }
    });
}

fn check(ui: &mut egui::Ui, selection: &mut AnalysisSelection, kind: AnalysisKind) {
    let mut selected = selection.checks.contains(&kind);
    if ui.checkbox(&mut selected, kind.label()).changed() {
        if selected {
            selection.checks.push(kind);
        } else {
            selection.checks.retain(|check| *check != kind);
        }
    }
}

/// The request to launch; a VM without a graphical base always runs the
/// program in the app terminal, whatever Run in the dialog remembers.
pub(crate) fn snapshot(
    request: &ExecRequest,
    args: &str,
    env: &str,
    graphical: bool,
) -> Result<ExecRequest, String> {
    request.analysis.validate()?;
    let mut request = request.clone();
    if !graphical {
        request.run_in = RunIn::AppTerminal;
    }
    request.args = args.lines().map(str::to_owned).collect();
    request.env = env
        .lines()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(request)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReportAction {
    Export {
        report_id: String,
        kind: Option<AnalysisKind>,
        format: AnalysisExportFormat,
    },
    ShowDirectory {
        report_id: String,
    },
    OpenGhidra {
        report_id: String,
    },
    Cancel(String),
    OpenSection {
        report_id: String,
        kind: AnalysisKind,
    },
    ReadSpecimen {
        report_id: String,
        offset: u64,
        data_len: usize,
    },
    /// Open Tools > Analysis tools to install a missing tool.
    OpenAnalysisTools,
    /// Make this report the one the Static Analysis panel shows.
    ShowReport {
        report_id: String,
    },
    /// Open the regex matches window over the report's strings.
    ScanRegex {
        report_id: String,
    },
    /// Show the same file's identity in Triage › Properties.
    OpenTriageProperties,
    /// Read a page of a category's full listing, filtered by `query` and
    /// ordered by `sort` over the whole listing.
    ReadListing {
        report_id: String,
        kind: AnalysisKind,
        start: u64,
        query: String,
        sort: Option<antinomie_monitor_core::ListingSort>,
    },
}

pub(crate) fn section_title(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Metadata => "Metadata",
        AnalysisKind::Structures => "Structures",
        AnalysisKind::Strings => "Strings",
        AnalysisKind::Entropy => "Entropy",
        AnalysisKind::Hardening => "Hardening",
        AnalysisKind::Rules => "Rules",
        AnalysisKind::Identification => "Identification",
        AnalysisKind::Capabilities => "Capabilities",
        AnalysisKind::Disassembly => "Disassembly",
        AnalysisKind::Decompilation => "Decompilation",
        AnalysisKind::Embedded => "Binwalk",
        AnalysisKind::Floss => "FLOSS",
        AnalysisKind::Unpacking => "Unpacking",
    }
}

/// True while a report's analysis is waiting for, or working on, its program.
pub(crate) fn in_progress(report: &AnalysisReport) -> bool {
    matches!(
        report.state,
        AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
    )
}

/// The word for a category that has no result yet while its report is in
/// progress.
pub(crate) fn pending_word(state: AnalysisState) -> &'static str {
    match state {
        AnalysisState::Acquiring | AnalysisState::Queued => "Queued…",
        _ => "Waiting…",
    }
}

/// "<done>/<total> checks completed" and the one check running now with its
/// tool and elapsed time, or None once the analysis has finished.
pub(crate) fn progress_text(report: &AnalysisReport) -> Option<String> {
    if !in_progress(report) {
        return None;
    }
    let done = report
        .sections
        .iter()
        .filter(|s| {
            matches!(
                s.state,
                AnalysisSectionState::Complete | AnalysisSectionState::Partial
            )
        })
        .count();
    let unavailable = report
        .sections
        .iter()
        .filter(|s| s.state == AnalysisSectionState::Unavailable)
        .count();
    let waiting = report
        .sections
        .iter()
        .filter(|s| s.state == AnalysisSectionState::Pending)
        .count();
    let status = match report.state {
        AnalysisState::Acquiring => "Copying the program from the guest".to_owned(),
        AnalysisState::Queued => "Queued for analysis".to_owned(),
        _ => report
            .sections
            .iter()
            .find(|s| s.state == AnalysisSectionState::Running)
            .map(|s| format!("{}: {}", section_title(s.kind), s.summary))
            .unwrap_or_else(|| {
                // Between two checks, or before the first one starts.
                if done + unavailable == 0 {
                    "Starting analysis worker"
                } else if waiting == 0 {
                    "Writing the report"
                } else {
                    "Starting the next check"
                }
                .to_owned()
            }),
    };
    Some(format!(
        "{done}/{} checks completed · {unavailable} unavailable · {waiting} waiting\n{status}",
        report.sections.len()
    ))
}

/// A spinner and the progress line while `report` is still being analyzed.
pub(crate) fn progress_banner(ui: &mut egui::Ui, report: &AnalysisReport) {
    if let Some(text) = progress_text(report) {
        crate::theme::loading_colored(ui, crate::theme::blue(), text);
    }
}

/// The Static Analysis panel without a report: what it is and how to get one.
/// `run_selected` tells a run without a report from no run at all.
pub(crate) fn no_report(ui: &mut egui::Ui, run_selected: bool) {
    use crate::theme;
    use egui::RichText;
    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(560.0);
        ui.label(
            RichText::new(egui_phosphor::regular::MAGNIFYING_GLASS)
                .size(32.0)
                .color(theme::muted()),
        );
        ui.label(
            RichText::new(if run_selected {
                "No static analysis report for this run"
            } else {
                "Select a run to view its static analysis report."
            })
            .strong()
            .color(theme::heading()),
        );
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Static analysis examines the program a run starts, without running it: \
                     metadata, structures, strings, entropy, hardening, rule matches and, \
                     with the analysis tools installed, disassembly and decompilation.",
                )
                .color(theme::muted()),
            )
            .wrap(),
        );
    });
    ui.add_space(10.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(560.0);
        egui::Frame::new()
            .fill(theme::raised())
            .stroke(egui::Stroke::new(1.0_f32, theme::line()))
            .corner_radius(6)
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    theme::section(ui, "To get a report");
                    for (step, text) in [
                        ("1", "Start the VM."),
                        ("2", "Open Run → Launch program."),
                        ("3", "Tick Static Analysis, choose the analyses, then Run."),
                        ("4", "Select the run in Run History: its report shows here."),
                    ] {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(step)
                                    .monospace()
                                    .color(theme::value(theme::ValueKind::Number)),
                            );
                            ui.label(text);
                        });
                    }
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Reports of earlier runs stay available from the selector above.",
                        )
                        .color(theme::muted()),
                    );
                });
            });
    });
}

/// Analyses still in progress besides the one shown, each with a spinner.
pub(crate) fn other_progress<'a>(
    ui: &mut egui::Ui,
    reports: impl IntoIterator<Item = &'a AnalysisReport>,
    shown: Option<&str>,
) {
    let mut seen = Vec::new();
    for report in reports {
        if Some(report.id.as_str()) == shown || seen.contains(&&report.id) {
            continue;
        }
        seen.push(&report.id);
        if let Some(text) = progress_text(report) {
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Spinner::new());
                ui.colored_label(
                    crate::theme::muted(),
                    format!("{}: {text}", report.source_path),
                )
                .on_hover_text(format!("Report {}", report.id));
            });
        }
    }
}

#[cfg(test)]
mod identity_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_capture_clears_when_guest_or_launch_session_cannot_capture_target() {
        for (supported, run_in) in [
            (false, RunIn::AppTerminal),
            (true, RunIn::GuestDesktopTerminal),
        ] {
            let ctx = egui::Context::default();
            let mut request = ExecRequest {
                run_in,
                core_dump_on_exit: true,
                ..ExecRequest::default()
            };
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    capture_selection(
                        ui,
                        &mut request,
                        LaunchCapabilities {
                            graphical: false,
                            core_on_exit: supported,
                            debug_on_start: false,
                            core_limits: None,
                            core_default_mib: 256,
                        },
                    )
                });
            });
            assert!(!request.core_dump_on_exit);
        }
        let ctx = egui::Context::default();
        let mut request = ExecRequest {
            core_dump_on_exit: true,
            ..ExecRequest::default()
        };
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                capture_selection(
                    ui,
                    &mut request,
                    LaunchCapabilities {
                        graphical: false,
                        core_on_exit: true,
                        debug_on_start: false,
                        core_limits: None,
                        core_default_mib: 256,
                    },
                )
            });
        });
        assert!(request.core_dump_on_exit);
    }

    #[test]
    fn debug_on_start_is_offered_only_where_it_can_work() {
        for (supported, run_in, kept) in [
            (true, RunIn::AppTerminal, true),
            (false, RunIn::AppTerminal, false),
            (true, RunIn::GuestDesktop, false),
        ] {
            let ctx = egui::Context::default();
            let mut request = ExecRequest {
                run_in,
                debug_on_start: true,
                ..ExecRequest::default()
            };
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| debugger_selection(ui, &mut request, supported));
            });
            assert_eq!(request.debug_on_start, kept);
        }
    }

    fn report(
        state: AnalysisState,
        sections: &[(AnalysisKind, AnalysisSectionState)],
    ) -> AnalysisReport {
        AnalysisReport {
            id: "report".into(),
            state,
            source_path: "/bin/true".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: sections
                .iter()
                .map(|&(kind, state)| {
                    let mut section = antinomie_monitor_core::AnalysisSection::new(kind);
                    section.state = state;
                    section
                })
                .collect(),
            layer: None,
            specimen_source: None,
        }
    }

    #[test]
    fn progress_counts_checks_and_names_the_one_running_until_finished() {
        let sections = [
            (AnalysisKind::Metadata, AnalysisSectionState::Complete),
            (AnalysisKind::Strings, AnalysisSectionState::Pending),
            (AnalysisKind::Entropy, AnalysisSectionState::Pending),
        ];
        assert_eq!(
            progress_text(&report(AnalysisState::Running, &sections)).as_deref(),
            Some("1/3 checks completed · 0 unavailable · 2 waiting\nStarting the next check")
        );
        assert_eq!(
            progress_text(&report(AnalysisState::Queued, &sections[..1])).as_deref(),
            Some("1/1 checks completed · 0 unavailable · 0 waiting\nQueued for analysis")
        );
        assert!(progress_text(&report(AnalysisState::Acquiring, &sections))
            .unwrap()
            .contains("Copying the program from the guest"));
        let fresh = [(AnalysisKind::Metadata, AnalysisSectionState::Pending)];
        assert!(progress_text(&report(AnalysisState::Running, &fresh))
            .unwrap()
            .ends_with("Starting analysis worker"));
        let finished = [(AnalysisKind::Metadata, AnalysisSectionState::Complete)];
        assert!(progress_text(&report(AnalysisState::Running, &finished))
            .unwrap()
            .ends_with("Writing the report"));
        let mut active = report(AnalysisState::Running, &sections);
        active.sections[1].state = AnalysisSectionState::Running;
        active.sections[1].summary = "Built-in analysis · tool 3s · check 3s elapsed".into();
        active.sections[2].state = AnalysisSectionState::Unavailable;
        assert_eq!(progress_text(&active).unwrap(), "1/3 checks completed · 1 unavailable · 0 waiting\nStrings: Built-in analysis · tool 3s · check 3s elapsed");
        for state in [
            AnalysisState::Complete,
            AnalysisState::Partial,
            AnalysisState::Unavailable,
            AnalysisState::Cancelled,
        ] {
            assert_eq!(progress_text(&report(state, &sections)), None);
        }
    }

    #[test]
    fn launch_selection_is_owned_and_empty_enabled_selection_is_rejected() {
        let mut draft = ExecRequest::default();
        assert!(!draft.analysis.enabled);
        assert_eq!(draft.analysis.checks, AnalysisKind::TRIAGE);
        draft.analysis.enabled = true;
        let launched = snapshot(&draft, "first\nsecond", "A=B", false).unwrap();
        draft.analysis.checks.clear();
        assert_eq!(launched.analysis.checks, AnalysisKind::TRIAGE);
        assert_eq!(launched.args, ["first", "second"]);
        assert!(snapshot(&draft, "", "", false).is_err());
        draft.analysis.enabled = false;
        assert!(snapshot(&draft, "", "", false).is_ok());
    }

    #[test]
    fn master_checkbox_accepts_keyboard_toggle_and_retains_individual_choices() {
        let ctx = egui::Context::default();
        let mut choices = AnalysisSelection::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                selection(ui, &mut choices, &[], &mut false).request_focus();
            });
        });
        for enabled in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    events: vec![egui::Event::Key {
                        key: egui::Key::Space,
                        physical_key: None,
                        pressed: true,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }],
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        selection(ui, &mut choices, &[], &mut false);
                    });
                },
            );
            assert_eq!(choices.enabled, enabled);
            assert_eq!(choices.checks, AnalysisKind::TRIAGE);
            let _ = ctx.run(
                egui::RawInput {
                    events: vec![egui::Event::Key {
                        key: egui::Key::Space,
                        physical_key: None,
                        pressed: false,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    }],
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        selection(ui, &mut choices, &[], &mut false);
                    });
                },
            );
        }
    }

    #[test]
    fn collapsing_triage_tree_preserves_checked_leaves() {
        let ctx = egui::Context::default();
        let mut choices = AnalysisSelection {
            enabled: true,
            ..Default::default()
        };
        let original = choices.checks.clone();
        let render = |choices: &mut AnalysisSelection, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 800.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        selection(ui, choices, &[], &mut false);
                    });
                },
            )
        };
        let find = |output: &egui::FullOutput, label: &str| {
            output.shapes.iter().find_map(|shape| {
                if let egui::Shape::Text(text) = &shape.shape {
                    (text.galley.text() == label).then(|| text.visual_bounding_rect())
                } else {
                    None
                }
            })
        };
        let mut output = render(&mut choices, Vec::new());
        for _ in 0..3 {
            output = render(&mut choices, Vec::new());
        }
        assert!(find(&output, AnalysisKind::Metadata.label()).is_some());
        for open in [false, true] {
            let target = find(&output, "Triage").unwrap().center();
            for pressed in [true, false] {
                output = render(
                    &mut choices,
                    vec![
                        egui::Event::PointerMoved(target),
                        egui::Event::PointerButton {
                            pos: target,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
            for _ in 0..20 {
                output = render(&mut choices, Vec::new());
            }
            assert_eq!(
                find(&output, AnalysisKind::Metadata.label()).is_some(),
                open
            );
            assert_eq!(choices.checks, original);
        }
    }
}
