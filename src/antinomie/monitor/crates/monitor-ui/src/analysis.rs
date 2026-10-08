//! Opt-in launch selection and retained, run-addressed analysis evidence.
use antinomie_monitor_core::{AnalysisKind, AnalysisSelection, ExecRequest};
use eframe::egui;
mod entropy;
mod records;
mod workspace;
pub(crate) use workspace::{workspace, workspace_section, WorkspaceState};

pub(crate) fn launch_fields(
    ui: &mut egui::Ui,
    request: &mut ExecRequest,
    args: &mut String,
    env: &mut String,
) {
    let spacing = ui.spacing().item_spacing.x;
    let min_pane = ui.text_style_height(&egui::TextStyle::Body) * 22.0;
    if ui.available_width() >= min_pane * 2.0 + spacing {
        ui.columns(2, |columns| {
            fields(&mut columns[0], request, args, env);
            selection(&mut columns[1], &mut request.analysis);
        });
    } else {
        fields(ui, request, args, env);
        ui.separator();
        selection(ui, &mut request.analysis);
    }
}

fn fields(ui: &mut egui::Ui, request: &mut ExecRequest, args: &mut String, env: &mut String) {
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
}

pub(crate) fn selection(ui: &mut egui::Ui, selection: &mut AnalysisSelection) -> egui::Response {
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

pub(crate) fn snapshot(
    request: &ExecRequest,
    args: &str,
    env: &str,
) -> Result<ExecRequest, String> {
    request.analysis.validate()?;
    let mut request = request.clone();
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
        let launched = snapshot(&draft, "first\nsecond", "A=B").unwrap();
        draft.analysis.checks.clear();
        assert_eq!(launched.analysis.checks, AnalysisKind::TRIAGE);
        assert_eq!(launched.args, ["first", "second"]);
        assert!(snapshot(&draft, "", "").is_err());
        draft.analysis.enabled = false;
        assert!(snapshot(&draft, "", "").is_ok());
    }

    #[test]
    fn master_checkbox_accepts_keyboard_toggle_and_retains_individual_choices() {
        let ctx = egui::Context::default();
        let mut choices = AnalysisSelection::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                selection(ui, &mut choices).request_focus();
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
                        selection(ui, &mut choices);
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
                        selection(ui, &mut choices);
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
                        selection(ui, choices);
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
