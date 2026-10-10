//! Opt-in launch selection and retained, run-addressed analysis evidence.
use antinomie_monitor_core::{
    analysis_tools::ToolStatus, AnalysisKind, AnalysisSelection, ExecRequest, RunIn,
};
use eframe::egui;
mod entropy;
mod listing_view;
mod records;
mod workspace;
pub(crate) use workspace::{workspace, workspace_section, WorkspaceState};

/// Program fields and the analysis selection; true when the user asked to
/// install a missing analysis tool. `graphical` offers the Run in choice,
/// which only a graphical base's session can use.
pub(crate) fn launch_fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    tools: &[ToolStatus],
    graphical: bool,
) -> bool {
    let mut install = false;
    let spacing = ui.spacing().item_spacing.x;
    let min_pane = ui.text_style_height(&egui::TextStyle::Body) * 22.0;
    if ui.available_width() >= min_pane * 2.0 + spacing {
        ui.columns(2, |columns| {
            fields(&mut columns[0], request, args, env, graphical);
            selection(&mut columns[1], &mut request.analysis, tools, &mut install);
        });
    } else {
        fields(ui, request, args, env, graphical);
        ui.separator();
        selection(ui, &mut request.analysis, tools, &mut install);
    }
    install
}

fn fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
    graphical: bool,
) {
    ui.heading("Program");
    for (label, value, multiline) in [
        ("Executable", &mut request.path, false),
        ("Arguments", args, true),
        ("Working directory", &mut request.cwd, false),
        ("Environment", env, true),
    ] {
        let label_response = ui.label(label);
        let edit = if multiline {
            egui::TextEdit::multiline(value).desired_rows(3)
        } else {
            egui::TextEdit::singleline(value)
        };
        ui.add(edit.desired_width(f32::INFINITY))
            .labelled_by(label_response.id)
            .on_hover_text(match label {
                "Arguments" => "One argument per line",
                "Environment" => "One NAME=value entry per line",
                _ => label,
            });
    }
    ui.horizontal_wrapped(|ui| {
        ui.label("UID");
        ui.add(egui::DragValue::new(&mut request.uid).range(0..=u32::MAX));
        ui.label("GID");
        ui.add(egui::DragValue::new(&mut request.gid).range(0..=u32::MAX));
    });
    if graphical {
        run_in(ui, &mut request.run_in);
    }
}

/// Where the program runs: this app's terminal or the guest's desktop.
fn run_in(ui: &mut egui::Ui, choice: &mut RunIn) {
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
    ui.colored_label(crate::theme::MUTED, choice.description());
    if choice.guest_desktop() {
        ui.colored_label(
            crate::theme::MUTED,
            "Log in on the VM display as this UID first. The run also records the launch script that joins the session.",
        );
    }
    if *choice == RunIn::GuestDesktopTerminal {
        ui.colored_label(
            crate::theme::MUTED,
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
    let (_, master, _) = egui::collapsing_header::CollapsingState::load_with_default_open(
        ui.ctx(),
        ui.make_persistent_id("analysis-tree"),
        true,
    )
    .show_header(ui, |ui| {
        ui.checkbox(&mut selection.enabled, "Static Analysis")
            .on_hover_text("Analyze the initial executable only")
    })
    .body(|ui| {
        ui.add_enabled_ui(selection.enabled, |ui| {
            for (label, kinds) in [
                ("Triage", AnalysisKind::TRIAGE),
                ("Deep analysis", AnalysisKind::DEEP),
            ] {
                egui::CollapsingHeader::new(label)
                    .id_salt(("analysis-branch", label))
                    .default_open(true)
                    .show(ui, |ui| {
                        for &kind in kinds {
                            check(ui, selection, kind);
                            needs_tool(ui, selection, kind, tools, install);
                        }
                    });
            }
        });
    });
    if let Err(reason) = selection.validate() {
        ui.colored_label(crate::theme::ERROR, reason);
    }
    master.inner
}

/// Under a selected category whose tool is missing: what it needs and a way
/// to install it.
fn needs_tool(
    ui: &mut egui::Ui,
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
    ui.horizontal_wrapped(|ui| {
        ui.add_space(24.0);
        ui.colored_label(crate::theme::WARN, format!("Needs {name}, not installed"));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
