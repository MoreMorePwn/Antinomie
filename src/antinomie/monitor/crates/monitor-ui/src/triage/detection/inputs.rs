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
        InputOutcome::Succeeded => ("Succeeded", theme::good()),
        InputOutcome::Failed => ("Failed", theme::error()),
        InputOutcome::Skipped => ("Skipped", theme::muted()),
    }
}

/// "2 succeeded, 1 failed, 1 skipped"; outcomes nobody had are left out.
pub(super) fn outcome_counts(inputs: &[ScannedInput]) -> String {
    [
        (InputOutcome::Succeeded, "succeeded"),
        (InputOutcome::Failed, "failed"),
        (InputOutcome::Skipped, "skipped"),
    ]
    .into_iter()
    .filter_map(|(kind, word)| {
        let count = inputs.iter().filter(|input| input.outcome == kind).count();
        (count > 0).then(|| format!("{count} {word}"))
    })
    .collect::<Vec<_>>()
    .join(", ")
}

/// Shown on a row whose capture or core is no longer on disk.
pub(super) const MISSING_NOTE: &str = "This capture or core was deleted or is no longer on disk. The result was computed before it went; this is not a clean result.";

/// Whether a row names a file whose presence is worth checking: a capture
/// (a run without captures lists a placeholder with no file at all) or a core.
fn checked_path(input: &ScannedInput) -> Option<&Path> {
    match input.kind {
        InputKind::Capture if input.path.extension().is_some() => Some(&input.path),
        InputKind::CoreDump => Some(&input.path),
        _ => None,
    }
}

/// How long a presence answer is kept before the files are looked at again.
const PRESENCE_KEEP: std::time::Duration = std::time::Duration::from_secs(30);

/// Which listed captures and cores are gone from disk. The file system is
/// read on a worker, never while a frame is drawn: on load, after a delete
/// and on a slow timer. Until an answer arrives a row reads as present.
#[derive(Default)]
pub(super) struct Presence {
    /// The paths the answer in `gone` was asked about.
    asked: Vec<PathBuf>,
    gone: std::collections::BTreeSet<PathBuf>,
    at: Option<std::time::Instant>,
    stale: bool,
    rx: Option<mpsc::Receiver<std::collections::BTreeSet<PathBuf>>>,
}

impl Presence {
    /// A file was deleted or the result changed: look again soon.
    pub(super) fn invalidate(&mut self) {
        self.stale = true;
    }

    /// Whether the saved result named a file that is no longer on disk.
    fn missing(&self, input: &ScannedInput) -> bool {
        checked_path(input).is_some_and(|path| self.gone.contains(path))
    }

    /// Take a finished answer and start a new probe when one is due.
    fn update(&mut self, ctx: &egui::Context, inputs: &[ScannedInput]) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(gone) => {
                    self.gone = gone;
                    self.rx = None;
                    self.at = Some(std::time::Instant::now());
                }
                Err(mpsc::TryRecvError::Disconnected) => self.rx = None,
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(100));
                    return;
                }
            }
        }
        let paths: Vec<PathBuf> = inputs
            .iter()
            .take(SHOWN)
            .filter_map(checked_path)
            .map(Path::to_path_buf)
            .collect();
        let due = self.stale
            || self.asked != paths
            || self.at.is_none_or(|at| at.elapsed() >= PRESENCE_KEEP);
        if paths.is_empty() {
            self.asked = paths;
            self.gone.clear();
            self.stale = false;
            return;
        }
        if !due {
            ctx.request_repaint_after(PRESENCE_KEEP);
            return;
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let repaint = ctx.clone();
        let probe = paths.clone();
        let spawned = std::thread::Builder::new()
            .name("triage-input-presence".into())
            .spawn(move || {
                let gone = probe
                    .into_iter()
                    .filter(|path| std::fs::symlink_metadata(path).is_err())
                    .collect();
                let _ = tx.send(gone);
                repaint.request_repaint_of(egui::ViewportId::ROOT);
            })
            .is_ok();
        self.asked = paths;
        self.stale = false;
        if spawned {
            self.rx = Some(rx);
            ctx.request_repaint_after(Duration::from_millis(100));
        }
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
        // A run without captures lists a placeholder with no file to open.
        InputKind::Capture if input.path.extension().is_none() => return None,
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

/// What a click on a row asked for.
#[derive(Default)]
struct RowAction {
    /// Where the name leads.
    route: Option<Route>,
    /// The row's Scan button: run this engine again.
    scan: bool,
    /// The row's Show log button.
    log: bool,
}

/// What the row's button says, and whether an engine scan is running.
#[derive(Clone, Copy)]
struct ScanState {
    /// A scan of this engine runs now; show the spinner instead of the button.
    running: bool,
    /// A scan can start (a run is selected and none is in progress).
    ready: bool,
}

/// One input. Failed and Skipped rows offer a Scan button, and Failed rows the
/// log; the engine scans every one of its inputs together, so Scan runs the
/// whole engine again.
fn row(
    ui: &mut egui::Ui,
    input: &ScannedInput,
    missing: bool,
    engine: &str,
    scan: ScanState,
) -> RowAction {
    // A deleted capture or core has nothing left to open.
    let target = target(input).filter(|_| !missing);
    let mut action = RowAction::default();
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
        if response
            .on_hover_text(hover(input, target.as_ref()))
            .clicked()
        {
            action.route = target;
        }
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
        if missing {
            ui.label(RichText::new("Evidence missing").color(theme::warn()))
                .on_hover_text(MISSING_NOTE);
        }
        if input.outcome == InputOutcome::Skipped && !input.reason.is_empty() {
            ui.label(RichText::new(&input.reason).small().color(theme::muted()));
        }
        if input.outcome == InputOutcome::Succeeded {
            if !input.reason.is_empty() {
                ui.label(RichText::new(&input.reason).small().color(theme::muted()));
            }
            return;
        }
        if scan.running {
            theme::loading_weak(ui, "Scanning…");
            return;
        }
        let label = if input.outcome == InputOutcome::Failed {
            "Scan again"
        } else {
            "Scan"
        };
        action.scan = ui
            .add_enabled(scan.ready, egui::Button::new(RichText::new(label).small()))
            .on_hover_text(format!(
                "Run the {engine} scan again for this run. It scans every {engine} input, not only this one."
            ))
            .clicked();
        if input.outcome == InputOutcome::Failed {
            action.log = ui
                .small_button("Show log")
                .on_hover_text("Open the result directory, which holds the detector log")
                .clicked();
        }
    });
    let wrapped = |ui: &mut egui::Ui, text: &str, color: egui::Color32| {
        ui.indent(("scanned-input-detail", &input.path, text), |ui| {
            ui.add(egui::Label::new(RichText::new(text).small().color(color)).wrap());
        });
    };
    if input.outcome == InputOutcome::Failed && !input.reason.is_empty() {
        wrapped(ui, &input.reason, theme::error());
    }
    if !input.detail.is_empty() {
        wrapped(ui, &input.detail, theme::muted());
    }
    if !input.warning.is_empty() {
        wrapped(ui, &input.warning, theme::warn());
    }
    action
}

impl View {
    /// The collapsible list below the rule sets, for the shown result.
    pub(super) fn scanned_inputs(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        scan: Option<&ArchiveScan>,
    ) {
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
        let mut rescan = false;
        let mut log = false;
        let state = ScanState {
            running: self.is_scanning(index),
            ready: self.rx.is_none() && self.identity.is_some(),
        };
        let engine = name(self.selected);
        let presence = &mut self.presence;
        ui.indent(("detector-scanned-inputs", index), |ui| {
            let Some(inputs) = inputs else {
                ui.weak("This result was saved before scanned inputs were recorded. Scan again to list them.");
                return;
            };
            if inputs.is_empty() {
                ui.weak("Nothing was passed to the rules.");
                return;
            }
            ui.label(
                RichText::new(outcome_counts(inputs))
                    .small()
                    .color(theme::muted()),
            );
            presence.update(ui.ctx(), inputs);
            for input in inputs.iter().take(SHOWN) {
                let action = row(ui, input, presence.missing(input), engine, state);
                if chosen.is_none() {
                    chosen = action.route;
                }
                rescan |= action.scan;
                log |= action.log;
            }
            if inputs.len() > SHOWN {
                ui.weak(format!(
                    "{} more inputs are in the saved result but not listed here.",
                    engine::group_digits((inputs.len() - SHOWN) as u64)
                ));
            }
        });
        if rescan {
            self.scan_now(ui.ctx(), index, scan);
        }
        if log {
            if let Some((directory, _)) = &self.identity {
                let result = engine::result_directory(directory, self.selected);
                crate::evidence::reveal(ui.ctx(), &result);
            }
        }
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
                outcome: InputOutcome::Failed,
                reason:
                    "stopped after 3 blocks: memory scan reached its time / 512 MiB input budget"
                        .into(),
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
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
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
            "1 succeeded, 1 failed, 1 skipped",
            "Executable",
            "sample",
            "2048 bytes (2.0 KB)",
            "abababababab",
            "Succeeded",
            "memory.elf",
            "Failed",
            "stopped after 3 blocks: memory scan reached its time / 512 MiB input budget",
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
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
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
                    egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
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
                egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
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

    /// Presses the primary button on the first text equal to `label`.
    fn click(view: &mut View, ctx: &egui::Context, label: &str) {
        let mut position = None;
        for shape in frames(ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
        }) {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                if text == label && position.is_none() {
                    position = Some(rect.center());
                }
            });
        }
        let position = position.unwrap_or_else(|| panic!("{label} is not painted"));
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
                    egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
                },
            );
        }
    }

    fn run_view() -> View {
        let mut view = view_without_run();
        view.identity = Some((
            PathBuf::from("/nonexistent/run"),
            antinomie_monitor_core::analysis::detection::Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
        ));
        view
    }

    fn view_without_run() -> View {
        let mut view = view(Some(inputs()));
        view.inputs_open[0] = true;
        view
    }

    #[test]
    fn failed_and_skipped_rows_offer_scan_and_succeeded_rows_do_not() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = run_view();
        let output = frames(&ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
        });
        let (mut again, mut scan, mut log) = (0, 0, 0);
        for shape in &output {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, _| {
                again += usize::from(text == "Scan again");
                scan += usize::from(text == "Scan");
                log += usize::from(text == "Show log");
            });
        }
        // Three rows: the Failed one has both buttons, the Skipped one Scan,
        // and the Succeeded sample none.
        assert_eq!((again, scan, log), (1, 1, 1), "{}", rendered_text(&output));
    }

    #[test]
    fn the_scan_button_starts_the_engine_and_shows_the_spinner_while_it_runs() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = run_view();
        assert!(view.busy.is_none());
        click(&mut view, &ctx, "Scan again");
        assert_eq!(view.busy, Some(0), "the YARA scan started");
        assert_eq!(view.phase[0], "running");
        // While it runs the rows show a spinner and no Scan button.
        let output = frames(&ctx, 2, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.scanned_inputs(ui, 0, None));
        });
        let text = rendered_text(&output);
        assert!(text.contains("Scanning…"), "{text}");
        assert!(!text.contains("Scan again"), "{text}");
        assert_eq!(
            theme::spinners_in(&output),
            2,
            "one per Failed or Skipped row"
        );
        // With no run selected the button is disabled and starts nothing.
        let mut idle = view_without_run();
        click(&mut idle, &ctx, "Scan again");
        assert!(idle.busy.is_none());
    }

    #[test]
    fn rows_say_why_and_the_sigma_row_carries_the_coverage_warning() {
        let ctx = egui::Context::default();
        let rows = vec![
            ScannedInput {
                kind: InputKind::EventJournal,
                path: PathBuf::from("/runs/r/triage-events.jsonl"),
                detail: "3 events · unmapped_thing 3".into(),
                warning: antinomie_monitor_core::analysis::detection::SIGMA_COVERAGE_WARNING.into(),
                ..ScannedInput::default()
            },
            ScannedInput {
                kind: InputKind::Capture,
                path: PathBuf::from("/runs/r/net.pcap"),
                outcome: InputOutcome::Skipped,
                reason: "no packets captured".into(),
                ..ScannedInput::default()
            },
        ];
        let mut view = view(Some(rows));
        view.inputs_open[0] = true;
        let text = shown(&mut view, &ctx);
        assert!(text.contains("1 succeeded, 1 skipped"), "{text}");
        assert!(
            text.contains("may not cover everything a Sysmon or auditd log would contain"),
            "{text}"
        );
        assert!(text.contains("no packets captured"), "{text}");
        assert!(!text.to_lowercase().contains("partial"), "{text}");
    }

    /// Draw until the worker's answer shows `count` missing rows.
    fn shown_until_missing(view: &mut View, ctx: &egui::Context, count: usize) -> String {
        for _ in 0..200 {
            let text = shown(view, ctx);
            if text.matches("Evidence missing").count() == count {
                return text;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        shown(view, ctx)
    }

    #[test]
    fn a_deleted_capture_or_core_reads_as_missing_evidence_and_does_not_open() {
        let dir = std::env::temp_dir().join(format!("ant-missing-input-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kept = dir.join("kept.pcap");
        std::fs::write(&kept, b"pcap").unwrap();
        let gone = dir.join("gone.pcap");
        let core = dir.join("core/process.elf");
        let rows = vec![
            ScannedInput::new(InputKind::Capture, &kept),
            ScannedInput::new(InputKind::Capture, &gone),
            ScannedInput::new(InputKind::CoreDump, &core),
            // The placeholder of a run without captures has no file at all.
            ScannedInput::new(InputKind::Capture, dir.join("network")),
        ];
        let ctx = egui::Context::default();
        let mut view = view(Some(rows));
        view.inputs_open[0] = true;
        let text = shown_until_missing(&mut view, &ctx, 2);
        assert_eq!(text.matches("Evidence missing").count(), 2, "{text}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn drawing_frames_does_not_touch_the_file_system() {
        let dir = std::env::temp_dir().join(format!("ant-presence-frames-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kept = dir.join("kept.pcap");
        std::fs::write(&kept, b"pcap").unwrap();
        let ctx = egui::Context::default();
        let mut view = view(Some(vec![ScannedInput::new(InputKind::Capture, &kept)]));
        view.inputs_open[0] = true;
        // The first answer arrives: nothing is missing.
        let text = shown_until_missing(&mut view, &ctx, 0);
        assert_eq!(text.matches("Evidence missing").count(), 0, "{text}");
        for _ in 0..200 {
            if view.presence.rx.is_none() {
                break;
            }
            shown(&mut view, &ctx);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(view.presence.rx.is_none(), "the first probe never finished");
        // The file goes. Frames drawn now answer from the cache: a stat per
        // row per frame would notice at once.
        std::fs::remove_file(&kept).unwrap();
        for _ in 0..50 {
            let text = shown(&mut view, &ctx);
            assert!(!text.contains("Evidence missing"), "{text}");
            assert!(view.presence.rx.is_none(), "a frame started a probe");
        }
        // A delete event refreshes it, off the frame.
        view.evidence_deleted();
        let text = shown_until_missing(&mut view, &ctx, 1);
        assert_eq!(text.matches("Evidence missing").count(), 1, "{text}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
