// SPDX-License-Identifier: MIT
//! Detection > Scanned inputs: exactly what the last scan passed to the
//! rules, so a count such as "1 object evaluated" can be checked.
use super::*;
use crate::triage::{OpenInput, OPEN_INPUT};
use antinomie_monitor_core::analysis::detection::{InputKind, InputOutcome, ScannedInput};
use egui_phosphor::regular as icon;

/// Rows drawn at once; a run can recover thousands of files.
const SHOWN: usize = 200;

pub(super) fn title(inputs: Option<&[ScannedInput]>) -> String {
    match inputs {
        None => "Scanned inputs: not recorded".to_owned(),
        Some(inputs) => format!("Scanned inputs ({})", inputs.len()),
    }
}

fn symbol(kind: InputKind) -> &'static str {
    match kind {
        InputKind::Executable => icon::FILE_CODE,
        InputKind::CoreDump => icon::CPU,
        InputKind::MemoryDump => icon::MEMORY,
        InputKind::RecoveredFile => icon::FILE,
        InputKind::Capture => icon::NETWORK,
        InputKind::EventJournal => icon::LIST_BULLETS,
    }
}

fn outcome(outcome: InputOutcome) -> (&'static str, egui::Color32) {
    match outcome {
        InputOutcome::Scanned => ("Scanned", theme::good()),
        InputOutcome::Partial => ("Partial", theme::warn()),
        InputOutcome::Skipped => ("Skipped", theme::muted()),
    }
}

/// Where a click on the row goes.
#[derive(Debug, PartialEq)]
pub(super) enum Route {
    /// A panel or folder the app opens.
    Open(OpenInput),
    /// The event journal viewer here, pinned to the digest the scan read.
    Journal(Option<String>),
}

pub(super) fn target(input: &ScannedInput) -> Option<Route> {
    let parent = || input.path.parent().map(Path::to_path_buf);
    let open = match input.kind {
        InputKind::Executable => OpenInput::StaticAnalysis,
        InputKind::Capture => OpenInput::Capture(input.path.clone()),
        InputKind::CoreDump => OpenInput::Core(input.path.clone()),
        InputKind::MemoryDump => OpenInput::Memory(parent()?),
        InputKind::RecoveredFile => OpenInput::Folder(parent()?),
        InputKind::EventJournal => return Some(Route::Journal(input.sha256.clone())),
    };
    Some(Route::Open(open))
}

fn hover(input: &ScannedInput, target: Option<&Route>) -> String {
    let mut text = input.path.display().to_string();
    if let Some(target) = target {
        text.push_str(match target {
            Route::Open(OpenInput::StaticAnalysis) => "\nClick to open in Static Analysis",
            Route::Open(OpenInput::Capture(_)) => "\nClick to open in Network",
            Route::Open(OpenInput::Core(_)) => "\nClick to open in Core dumps",
            Route::Open(OpenInput::Memory(_)) => "\nClick to open in Memory",
            Route::Open(OpenInput::Folder(_)) => "\nClick to open its folder",
            Route::Journal(_) => "\nClick to inspect the events Sigma evaluated",
        });
    }
    text
}

/// One input; returns where to go when its name was clicked.
fn row(ui: &mut egui::Ui, input: &ScannedInput) -> Option<Route> {
    let target = target(input);
    let mut clicked = false;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(symbol(input.kind)).color(theme::blue()));
        ui.label(RichText::new(input.kind.label()).color(theme::muted()));
        let name = if input.name.is_empty() {
            input
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| input.path.display().to_string())
        } else {
            input.name.clone()
        };
        let response = if target.is_some() {
            ui.link(name)
        } else {
            ui.label(RichText::new(name).color(theme::text()))
        };
        clicked = response
            .on_hover_text(hover(input, target.as_ref()))
            .clicked();
        if let Some(size) = input.size {
            ui.label(RichText::new(crate::network_view::format_bytes(size)).color(theme::muted()));
        }
        if let Some(sha256) = &input.sha256 {
            ui.label(
                RichText::new(sha256.chars().take(12).collect::<String>())
                    .monospace()
                    .small()
                    .color(theme::muted()),
            )
            .on_hover_text(format!("SHA-256 {sha256}"));
        }
        let (text, color) = outcome(input.outcome);
        ui.label(RichText::new(text).color(color));
        if !input.reason.is_empty() {
            ui.label(RichText::new(&input.reason).small().color(theme::muted()));
        }
    });
    if !input.detail.is_empty() {
        ui.indent(("scanned-input-detail", &input.path), |ui| {
            ui.add(
                egui::Label::new(RichText::new(&input.detail).small().color(theme::muted())).wrap(),
            );
        });
    }
    clicked.then_some(target).flatten()
}

impl View {
    /// The collapsible list below the rule sets, for the shown result.
    pub(super) fn scanned_inputs(&mut self, ui: &mut egui::Ui, index: usize) {
        let Some(Ok(report)) = &self.results[index] else {
            return;
        };
        let inputs = report.inputs.as_deref();
        let open = self.inputs_open[index];
        let caret = if open {
            icon::CARET_DOWN
        } else {
            icon::CARET_RIGHT
        };
        let toggle = ui
            .add(
                egui::Button::new(
                    RichText::new(format!("{caret} {}", title(inputs))).color(theme::text()),
                )
                .frame(false)
                .truncate(),
            )
            .on_hover_text("Show or hide what the last scan passed to the rules")
            .clicked();
        if toggle {
            self.inputs_open[index] = !open;
        }
        if !open {
            return;
        }
        let mut chosen = None;
        ui.indent(("detector-scanned-inputs", index), |ui| {
            let Some(inputs) = inputs else {
                ui.weak("This result was saved before scanned inputs were recorded. Scan again to list them.");
                return;
            };
            if inputs.is_empty() {
                ui.weak("Nothing was passed to the rules.");
                return;
            }
            let count = |kind| inputs.iter().filter(|input| input.outcome == kind).count();
            ui.label(
                RichText::new(format!(
                    "{} scanned · {} partial · {} skipped",
                    count(InputOutcome::Scanned),
                    count(InputOutcome::Partial),
                    count(InputOutcome::Skipped)
                ))
                .small()
                .color(theme::muted()),
            );
            for input in inputs.iter().take(SHOWN) {
                if let Some(target) = row(ui, input) {
                    chosen = Some(target);
                }
            }
            if inputs.len() > SHOWN {
                ui.weak(format!(
                    "{} more inputs are in the saved result but not listed here.",
                    engine::group_digits((inputs.len() - SHOWN) as u64)
                ));
            }
        });
        match chosen {
            Some(Route::Open(target)) => ui
                .ctx()
                .data_mut(|data| data.insert_temp(egui::Id::new(OPEN_INPUT), target)),
            Some(Route::Journal(scanned)) => self.journal.open(ui.ctx(), scanned, None),
            None => {}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::super::tests::{frames, rendered_text, report};
    use super::*;

    fn inputs() -> Vec<ScannedInput> {
        vec![
            ScannedInput {
                kind: InputKind::Executable,
                path: PathBuf::from("/runs/r/analysis"),
                name: "sample".into(),
                size: Some(2048),
                sha256: Some("ab".repeat(32)),
                ..ScannedInput::default()
            },
            ScannedInput {
                kind: InputKind::MemoryDump,
                path: PathBuf::from("/runs/r/memory/memory.elf"),
                outcome: InputOutcome::Partial,
                reason: "mapped ranges missing from the dump were excluded".into(),
                detail: "3 blocks of up to 64 MiB · 2 ranges not captured".into(),
                ..ScannedInput::default()
            },
            ScannedInput {
                kind: InputKind::RecoveredFile,
                path: PathBuf::from("/runs/r/memory/files"),
                outcome: InputOutcome::Skipped,
                reason: "recovered-file scanning is off".into(),
                ..ScannedInput::default()
            },
        ]
    }

    fn view(inputs: Option<Vec<ScannedInput>>) -> View {
        let mut view = View::default();
        let mut result = report(vec![]);
        result.inputs = inputs;
        view.results[0] = Some(Ok(result));
        view
    }

    fn shown(view: &mut View, ctx: &egui::Context) -> String {
        rendered_text(&frames(ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0));
        }))
    }

    #[test]
    fn the_title_counts_inputs_and_rows_show_size_digest_and_outcome() {
        let ctx = egui::Context::default();
        let mut view = view(Some(inputs()));
        let collapsed = shown(&mut view, &ctx);
        assert!(collapsed.contains("Scanned inputs (3)"), "{collapsed}");
        assert!(!collapsed.contains("sample"), "{collapsed}");
        view.inputs_open[0] = true;
        let text = shown(&mut view, &ctx);
        for expected in [
            "1 scanned · 1 partial · 1 skipped",
            "Executable",
            "sample",
            "2.0 KiB",
            "abababababab",
            "Scanned",
            "memory.elf",
            "Partial",
            "3 blocks of up to 64 MiB · 2 ranges not captured",
            "Skipped",
            "recovered-file scanning is off",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
    }

    #[test]
    fn results_saved_before_inputs_say_the_list_was_not_recorded() {
        let ctx = egui::Context::default();
        let mut view = view(None);
        view.inputs_open[0] = true;
        let text = shown(&mut view, &ctx);
        assert!(text.contains("Scanned inputs: not recorded"), "{text}");
        assert!(text.contains("Scan again to list them"), "{text}");
        let mut empty = super::View::default();
        assert_eq!(shown(&mut empty, &ctx), "", "no result, no section");
    }

    #[test]
    fn rows_open_where_each_input_is_viewed() {
        let rows = inputs();
        assert_eq!(
            target(&rows[0]),
            Some(Route::Open(OpenInput::StaticAnalysis))
        );
        assert_eq!(
            target(&rows[1]),
            Some(Route::Open(OpenInput::Memory(PathBuf::from(
                "/runs/r/memory"
            ))))
        );
        assert_eq!(
            target(&rows[2]),
            Some(Route::Open(OpenInput::Folder(PathBuf::from(
                "/runs/r/memory"
            ))))
        );
        let capture = ScannedInput::new(InputKind::Capture, "/runs/r/net.pcap");
        assert_eq!(
            target(&capture),
            Some(Route::Open(OpenInput::Capture(PathBuf::from(
                "/runs/r/net.pcap"
            ))))
        );
        let mut journal = ScannedInput::new(InputKind::EventJournal, "/runs/r/triage-events.jsonl");
        journal.sha256 = Some("ab".into());
        assert_eq!(target(&journal), Some(Route::Journal(Some("ab".into()))));

        // Clicking a name leaves the target for the app.
        let ctx = egui::Context::default();
        let mut view = view(Some(rows));
        view.inputs_open[0] = true;
        let mut position = None;
        for shape in frames(&ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0));
        }) {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                if text == "sample" {
                    position = Some(rect.center());
                }
            });
        }
        let position = position.expect("sample row");
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 800.0),
                    )),
                    events: vec![
                        egui::Event::PointerMoved(position),
                        egui::Event::PointerButton {
                            pos: position,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0));
                },
            );
        }
        let chosen = ctx.data_mut(|data| data.get_temp::<OpenInput>(egui::Id::new(OPEN_INPUT)));
        assert_eq!(chosen, Some(OpenInput::StaticAnalysis));
    }

    #[test]
    fn long_lists_draw_a_bounded_number_of_rows() {
        let ctx = egui::Context::default();
        let many = (0..SHOWN + 5)
            .map(|index| {
                ScannedInput::new(
                    InputKind::RecoveredFile,
                    format!("/runs/r/memory/files/{index}"),
                )
            })
            .collect();
        let mut view = view(Some(many));
        view.inputs_open[0] = true;
        // Tall enough that no row is culled.
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 40_000.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0));
            },
        );
        let text = rendered_text(&output.shapes);
        assert!(
            text.contains(&format!("Scanned inputs ({})", SHOWN + 5)),
            "{text}"
        );
        assert!(
            text.contains("5 more inputs are in the saved result"),
            "{text}"
        );
        assert_eq!(text.matches("Recovered file").count(), SHOWN);
    }
}
