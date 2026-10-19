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
mod workspace;
pub(crate) use listing_view::{export_ghidra_text, index_ghidra_markers};
pub(crate) use listing_view::{listing_fields, listing_row_with};
pub(crate) use workspace::{workspace, workspace_section, WorkspaceState};

#[derive(Clone, Copy)]
pub(crate) struct LaunchCapabilities {
    pub graphical: bool,
    pub core_on_exit: bool,
}

/// Program fields and the analysis selection; true when the user asked to
/// install a missing analysis tool. `capabilities.graphical` offers the Run in choice,
/// which only a graphical base's session can use.
pub(crate) fn launch_fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    tools: &[ToolStatus],
    capabilities: LaunchCapabilities,
) -> bool {
    let mut install = false;
    let spacing = ui.spacing().item_spacing.x;
    let min_pane = ui.text_style_height(&egui::TextStyle::Body) * 22.0;
    if ui.available_width() >= min_pane * 2.0 + spacing {
        ui.columns(2, |columns| {
            fields(&mut columns[0], request, args, env, capabilities.graphical);
            crate::theme::section(&mut columns[1], "Analysis");
            selection(&mut columns[1], &mut request.analysis, tools, &mut install);
            capture_selection(&mut columns[1], request, capabilities.core_on_exit);
        });
    } else {
        fields(ui, request, args, env, capabilities.graphical);
        ui.add_space(6.0);
        crate::theme::section(ui, "Analysis");
        selection(ui, &mut request.analysis, tools, &mut install);
        capture_selection(ui, request, capabilities.core_on_exit);
    }
    install
}

fn capture_selection(ui: &mut egui::Ui, request: &mut ExecRequest, core_supported: bool) {
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
    .on_hover_text("Capture the launched root process before exit, including thread registers and selected memory. Linux x86-64; memory is filtered and bounded to 64 MiB, so captures may be partial. Some fatal exits, including SIGKILL, may leave register context unavailable. Thread synchronization and page faults may delay exit.")
    .on_disabled_hover_text(core_unavailable_reason(core_supported));
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
) {
    crate::theme::section(ui, "Program");
    let label_width = ui.text_style_height(&egui::TextStyle::Body) * 8.5;
    egui::Grid::new("run-program-fields")
        .num_columns(2)
        .spacing([12.0, 8.0])
        .min_col_width(label_width)
        .show(ui, |ui| {
            for (label, value, multiline, hint) in [
                ("Executable", &mut request.path, false, "/path/in/guest"),
                ("Arguments", args, true, "One argument per line"),
                ("Working directory", &mut request.cwd, false, "/"),
                ("Environment", env, true, "One NAME=value entry per line"),
            ] {
                let label_response = ui.label(label);
                let edit = if multiline {
                    egui::TextEdit::multiline(value).desired_rows(3)
                } else {
                    egui::TextEdit::singleline(value)
                };
                ui.add(
                    edit.margin(crate::theme::TEXT_EDIT_MARGIN)
                        .font(egui::TextStyle::Monospace)
                        .hint_text(egui::RichText::new(hint).color(crate::theme::muted()))
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label_response.id)
                .on_hover_text(match label {
                    "Arguments" => "One argument per line",
                    "Environment" => "One NAME=value entry per line",
                    _ => label,
                });
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
        ui.label(egui::RichText::new("UID").color(crate::theme::muted()));
        ui.add(egui::DragValue::new(&mut request.uid).range(0..=u32::MAX));
        ui.label(egui::RichText::new("GID").color(crate::theme::muted()));
        ui.add(egui::DragValue::new(&mut request.gid).range(0..=u32::MAX));
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
    /// Read a page of a category's full listing, filtered by `query`.
    ReadListing {
        report_id: String,
        kind: AnalysisKind,
        start: u64,
        query: String,
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
        _ => "Running…",
    }
}

/// "Analysis in progress: <categories without a result>", or None once the
/// analysis has finished.
pub(crate) fn progress_text(report: &AnalysisReport) -> Option<String> {
    if !in_progress(report) {
        return None;
    }
    let stage = match report.state {
        AnalysisState::Acquiring => " (copying the program from the guest)",
        AnalysisState::Queued => " (queued)",
        _ => "",
    };
    let pending: Vec<_> = report
        .sections
        .iter()
        .filter(|section| section.state == AnalysisSectionState::Pending)
        .map(|section| section_title(section.kind))
        .collect();
    Some(if pending.is_empty() {
        format!("Analysis in progress{stage}")
    } else {
        format!("Analysis in progress{stage}: {}", pending.join(", "))
    })
}

/// A spinner and the progress line while `report` is still being analyzed.
pub(crate) fn progress_banner(ui: &mut egui::Ui, report: &AnalysisReport) {
    if let Some(text) = progress_text(report) {
        ui.horizontal_wrapped(|ui| {
            ui.add(egui::Spinner::new());
            ui.colored_label(crate::theme::blue(), text);
        });
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
                egui::CentralPanel::default()
                    .show(ctx, |ui| capture_selection(ui, &mut request, supported));
            });
            assert!(!request.core_dump_on_exit);
        }
        let ctx = egui::Context::default();
        let mut request = ExecRequest {
            core_dump_on_exit: true,
            ..ExecRequest::default()
        };
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| capture_selection(ui, &mut request, true));
        });
        assert!(request.core_dump_on_exit);
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
        }
    }

    #[test]
    fn progress_names_categories_still_running_and_clears_when_finished() {
        let sections = [
            (AnalysisKind::Metadata, AnalysisSectionState::Complete),
            (AnalysisKind::Strings, AnalysisSectionState::Pending),
            (AnalysisKind::Entropy, AnalysisSectionState::Pending),
        ];
        assert_eq!(
            progress_text(&report(AnalysisState::Running, &sections)).as_deref(),
            Some("Analysis in progress: Strings, Entropy")
        );
        assert_eq!(
            progress_text(&report(AnalysisState::Queued, &sections[..1])).as_deref(),
            Some("Analysis in progress (queued)")
        );
        assert!(progress_text(&report(AnalysisState::Acquiring, &sections))
            .unwrap()
            .starts_with("Analysis in progress (copying the program from the guest): Strings"));
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
