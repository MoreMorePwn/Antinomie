// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Output files: what the sample's runs left behind (memory
//! dumps, core dumps, network captures), one row each with why it was saved,
//! where it is now and what can be done with it. Rows are read with the rest
//! of the window, so drawing never touches the disk.
use super::{parts, *};
use crate::widgets::{table, Tone};
use antinomie_monitor_core::RunArtifactState::{Complete, Partial};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::app::samples_page) enum Kind {
    Memory,
    Core,
    Capture,
    /// A VM snapshot a rule took during the run.
    Snapshot,
    /// A file a rule saved at the moment of an event.
    Saved,
    /// The static report of a run that was deleted.
    StaticReport,
}

impl Kind {
    pub(in crate::app::samples_page) fn label(self) -> &'static str {
        self.core().label()
    }

    fn open_label(self) -> &'static str {
        match self {
            Kind::Memory => "Open in Memory",
            Kind::Core => "Open in Core dumps",
            Kind::Capture => "Open in Network",
            Kind::Snapshot => "Open in Snapshots",
            Kind::Saved => "View",
            Kind::StaticReport => "Open",
        }
    }

    /// The window the file opens in; a snapshot has the VM's Snapshots
    /// window, which the app opens itself.
    fn panel(self) -> Option<crate::workspace::Panel> {
        match self {
            Kind::Memory => Some(crate::workspace::Panel::Memory),
            Kind::Core => Some(crate::workspace::Panel::CoreDump),
            Kind::Capture => Some(crate::workspace::Panel::Network),
            Kind::Snapshot | Kind::Saved | Kind::StaticReport => None,
        }
    }

    /// Why Open is not available for this kind, when it never is.
    fn open_unavailable(self) -> Option<&'static str> {
        match self {
            Kind::Saved => Some("Viewing a saved file is not available yet; use Open folder"),
            Kind::StaticReport => Some("Open the report from Static analysis in the Summary"),
            _ => None,
        }
    }
}

/// Where a file is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::app::samples_page) enum Availability {
    /// In the run's folder.
    InRun,
    /// Deleted through the app.
    Deleted,
    /// Not there, and not deleted through the app.
    Missing,
    /// Moved into the library when its run was deleted: where it is now, and
    /// when the run was deleted.
    Kept(PathBuf, u64),
    /// Left with the VM: a snapshot, or a recording file other runs use.
    WithVm,
    /// Copied into the sample's record.
    InRecord,
}

pub(in crate::app::samples_page) struct Output {
    pub(in crate::app::samples_page) number: usize,
    pub(in crate::app::samples_page) kind: Kind,
    pub(in crate::app::samples_page) path: PathBuf,
    pub(in crate::app::samples_page) size: Option<u64>,
    pub(in crate::app::samples_page) saved_because: String,
    pub(in crate::app::samples_page) availability: Availability,
    /// The state the run recorded ("Complete", "Partial" ...).
    pub(in crate::app::samples_page) state: String,
    /// Its SHA-256 when it is known without reading the file.
    pub(in crate::app::samples_page) hash: String,
    /// The file's name in the run.
    pub(in crate::app::samples_page) name: String,
    pub(in crate::app::samples_page) run_id: String,
    pub(in crate::app::samples_page) vm_id: String,
    /// The process or time it belongs to.
    pub(in crate::app::samples_page) context: String,
    /// When it was deleted, for a file deleted with its run.
    pub(in crate::app::samples_page) deleted_ms: Option<u64>,
}

/// The width the three action buttons of a row need on one line.
const ACTIONS_WIDTH: f32 = 380.0;

fn size_of(path: &std::path::Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.is_file() {
        return Some(meta.len());
    }
    // A memory dump is a folder: its files, one level deep.
    let mut total = 0u64;
    for entry in std::fs::read_dir(path).ok()?.flatten() {
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                total += meta.len();
            }
        }
    }
    Some(total)
}

fn row(
    number: usize,
    kind: Kind,
    path: PathBuf,
    deleted: bool,
    state: &str,
    because: &'static str,
) -> Output {
    let size = if deleted { None } else { size_of(&path) };
    Output {
        number,
        kind,
        availability: if deleted {
            Availability::Deleted
        } else if size.is_some() {
            Availability::InRun
        } else {
            Availability::Missing
        },
        path,
        size,
        saved_because: because.to_owned(),
        state: state.to_owned(),
        hash: String::new(),
        name: String::new(),
        run_id: String::new(),
        vm_id: String::new(),
        context: String::new(),
        deleted_ms: None,
    }
}

/// Every output file of the runs, newest run first, and what the runs that
/// were deleted left.
pub(in crate::app::samples_page) fn read(
    entries: &[RunEntry],
    kept: &[antinomie_monitor_core::samples::KeptArtifact],
) -> Vec<Output> {
    use antinomie_monitor_core::RunArtifactState as State;
    let state = |state: State, deleted: bool| -> String {
        if deleted {
            "Deleted".into()
        } else {
            match state {
                Complete => "Complete".into(),
                Partial => "Partial".into(),
                other => format!("{other:?}"),
            }
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let Some(artifacts) = &entry.artifacts else {
            continue;
        };
        if let Some(path) = &artifacts.memory_dump {
            out.push(row(
                entry.number,
                Kind::Memory,
                path.clone(),
                false,
                &state(artifacts.memory_state, false),
                "Memory dump on exit",
            ));
        }
        if artifacts.core_dump.is_some() || artifacts.core_deleted {
            out.push(row(
                entry.number,
                Kind::Core,
                artifacts.core_dump.clone().unwrap_or_default(),
                artifacts.core_deleted,
                &state(artifacts.core_state, artifacts.core_deleted),
                "Core dump on exit",
            ));
        }
        for path in &artifacts.network_captures {
            out.push(row(
                entry.number,
                Kind::Capture,
                path.clone(),
                false,
                &state(artifacts.network_state, false),
                "Network capture",
            ));
        }
        if artifacts.network_deleted && artifacts.network_captures.is_empty() {
            out.push(row(
                entry.number,
                Kind::Capture,
                PathBuf::new(),
                true,
                "Deleted",
                "Network capture",
            ));
        }
    }
    for output in &mut out {
        if let Some(entry) = entries.iter().find(|entry| entry.number == output.number) {
            output.run_id.clone_from(&entry.run.id);
            output.vm_id.clone_from(&entry.run.vm_id);
        }
        output.name = output
            .path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    }
    super::artifact_rows::extend(&mut out, entries, kept);
    out
}

/// What a click in the table asks for.
pub(in crate::app::samples_page) enum Act {
    Open(usize, Kind),
    GoToRun(usize),
}

/// Draw the section; returns what was clicked.
pub(in crate::app::samples_page) fn section(
    ui: &mut egui::Ui,
    data: &Data,
    font: f32,
) -> Option<Act> {
    let mut act = None;
    let present = data
        .outputs
        .iter()
        .filter(|output| output.is_present())
        .count();
    parts::section(ui, "Artifacts", Some(present), |ui| {
        if data.outputs.is_empty() {
            parts::muted_line(ui, "None.");
            return;
        }
        super::artifact_rows::request_hashes(ui.ctx(), data.data_dir(), &data.outputs);
        ui.horizontal_wrapped(|ui| {
            for kind in [
                Kind::Memory,
                Kind::Core,
                Kind::Capture,
                Kind::Snapshot,
                Kind::Saved,
                Kind::StaticReport,
            ] {
                let here = data
                    .outputs
                    .iter()
                    .filter(|o| o.kind == kind && o.is_present())
                    .count();
                let gone = data
                    .outputs
                    .iter()
                    .filter(|o| o.kind == kind && !o.is_present())
                    .count();
                if here + gone == 0 {
                    continue;
                }
                ui.label(RichText::new(here.to_string()).strong());
                let plural = kind.core().plural();
                ui.label(if here == 1 {
                    plural.trim_end_matches('s')
                } else {
                    plural
                });
                if gone > 0 {
                    ui.label(theme::hint_text(format!("+{gone} gone")));
                }
                ui.add_space(12.0);
            }
        });
        ui.add_space(4.0);
        let body = egui::TextStyle::Body.resolve(ui.style());
        let widest = |title: &str, text: &dyn Fn(&Output) -> String| {
            parts::fitted(
                ui,
                &body,
                std::iter::once(title.to_owned()).chain(data.outputs.iter().map(text)),
            )
        };
        let file = widest("File", &|output| output.kind.label().to_owned());
        let because = widest("Saved because", &|output| output.saved_because.clone());
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let hash = parts::fitted(ui, &mono, ["SHA-256".to_owned(), "00000000".to_owned()]);
        let size = widest("Size", &|output| {
            output.size.map_or("–".to_owned(), crate::values::file_size)
        });
        // The three buttons need about this much; a narrower last column
        // puts them on two lines, in taller rows, instead of cutting them.
        let fixed = file + hash + 70.0 + because + size + 140.0 + ui.spacing().item_spacing.x * 6.0;
        let roomy = ui.available_width() - fixed >= ACTIONS_WIDTH;
        parts::on_surface(ui, |ui| {
            parts::mini_table(ui, "sample_summary_outputs")
                .sense(egui::Sense::click())
                .column(egui_extras::Column::exact(file))
                .column(egui_extras::Column::exact(hash))
                .column(egui_extras::Column::exact(70.0))
                .column(egui_extras::Column::exact(because))
                .column(egui_extras::Column::exact(size))
                .column(egui_extras::Column::exact(140.0))
                .column(egui_extras::Column::remainder().at_least(60.0))
                .header(table::header_height(font), |mut header| {
                    for title in [
                        "File",
                        "SHA-256",
                        "Run",
                        "Saved because",
                        "Size",
                        "Availability",
                        "",
                    ] {
                        header.col(|ui| table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(
                        table::row_height(font) + if roomy { 6.0 } else { 34.0 },
                        data.outputs.len(),
                        |mut row| {
                            let output = &data.outputs[row.index()];
                            let here = output.availability == Availability::InRun;
                            let run_there = data
                                .runs
                                .iter()
                                .any(|entry| entry.number == output.number && entry.folder);
                            row.col(|ui| {
                                ui.label(output.kind.label());
                            });
                            row.col(|ui| {
                                table::cell(ui, table::Cell::Mono, &output.short()).on_hover_text(
                                    if output.hash.is_empty() {
                                        "SHA-256 of the file"
                                    } else {
                                        output.hash.as_str()
                                    },
                                );
                            });
                            row.col(|ui| {
                                ui.label(if output.number == 0 {
                                    "–".to_owned()
                                } else {
                                    parts::run_name(output.number)
                                });
                            });
                            row.col(|ui| {
                                ui.label(&output.saved_because);
                            });
                            row.col(|ui| {
                                ui.label(
                                    output.size.map_or("–".to_owned(), crate::values::file_size),
                                );
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| match &output.availability {
                                    Availability::InRun => {
                                        widgets::chip(
                                            ui,
                                            format!("In run {} folder", output.number),
                                            if output.state == "Complete" {
                                                Tone::Good
                                            } else {
                                                Tone::Warn
                                            },
                                        )
                                        .on_hover_text(format!("State: {}", output.state));
                                    }
                                    Availability::Deleted => {
                                        widgets::chip(
                                            ui,
                                            match output.deleted_ms {
                                                Some(ms) => {
                                                    format!(
                                                        "Deleted by you · {}",
                                                        super::second(ms)
                                                    )
                                                }
                                                None => "Deleted by you".to_owned(),
                                            },
                                            Tone::Neutral,
                                        );
                                    }
                                    Availability::Kept(stored, ms) => {
                                        widgets::chip(ui, "Kept in Samples", Tone::Good)
                                            .on_hover_text(format!(
                                                "Moved when run {} was deleted, {}: {}",
                                                output.number,
                                                super::second(*ms),
                                                stored.display()
                                            ));
                                    }
                                    Availability::WithVm => {
                                        widgets::chip(ui, "With the VM", Tone::Info).on_hover_text(
                                            if output.kind == Kind::Snapshot {
                                                "A VM snapshot stays in the VM's snapshot tree"
                                            } else {
                                                "Left in the VM's recording"
                                            },
                                        );
                                    }
                                    Availability::InRecord => {
                                        widgets::chip(ui, "In the sample record", Tone::Info)
                                            .on_hover_text("Copied with the run's record");
                                    }
                                    Availability::Missing => {
                                        widgets::chip(ui, "Missing", Tone::Error)
                                            .on_hover_text("Not deleted through the app");
                                    }
                                });
                            });
                            row.col(|ui| {
                                ui.horizontal_wrapped(|ui| {
                                    let why = match output.availability {
                                        Availability::Deleted => "The file was deleted",
                                        Availability::Kept(..) => {
                                            "The file was moved into Samples; use Open folder"
                                        }
                                        Availability::InRecord => "Open it from the Summary",
                                        _ => "The file is missing",
                                    };
                                    let can_open = (here
                                        || output.availability == Availability::WithVm
                                            && output.kind == Kind::Snapshot)
                                        && run_there;
                                    let reason = output.kind.open_unavailable().unwrap_or(why);
                                    if ui
                                        .add_enabled(
                                            can_open && output.kind.open_unavailable().is_none(),
                                            egui::Button::new(output.kind.open_label()).small(),
                                        )
                                        .on_disabled_hover_text(if run_there {
                                            reason
                                        } else {
                                            "The run's folder was deleted"
                                        })
                                        .clicked()
                                    {
                                        act = Some(Act::Open(output.number, output.kind));
                                    }
                                    if ui
                                        .add_enabled(
                                            run_there,
                                            egui::Button::new("Go to run").small(),
                                        )
                                        .on_disabled_hover_text("The run's folder was deleted")
                                        .clicked()
                                    {
                                        act = Some(Act::GoToRun(output.number));
                                    }
                                    let folder = matches!(
                                        output.availability,
                                        Availability::InRun | Availability::Kept(..)
                                    ) && !output.path.as_os_str().is_empty();
                                    if ui
                                        .add_enabled(
                                            folder,
                                            egui::Button::new("Open folder").small(),
                                        )
                                        .on_disabled_hover_text(why)
                                        .clicked()
                                    {
                                        crate::evidence::reveal(ui.ctx(), &output.path);
                                    }
                                });
                            });
                            row.response().context_menu(|ui| {
                                let why = match output.availability {
                                    Availability::Deleted => "The file was deleted",
                                    _ => "The file is missing",
                                };
                                if ui
                                    .add_enabled(here, egui::Button::new(output.kind.open_label()))
                                    .on_disabled_hover_text(why)
                                    .clicked()
                                {
                                    act = Some(Act::Open(output.number, output.kind));
                                    ui.close_menu();
                                }
                                if ui.button("Go to run").clicked() {
                                    act = Some(Act::GoToRun(output.number));
                                    ui.close_menu();
                                }
                                if ui
                                    .add_enabled(here, egui::Button::new("Open folder"))
                                    .on_disabled_hover_text(why)
                                    .clicked()
                                {
                                    crate::evidence::reveal(ui.ctx(), &output.path);
                                    ui.close_menu();
                                }
                                ui.separator();
                                let is_file = here && output.path.is_file();
                                if ui
                                    .add_enabled(is_file, egui::Button::new("Copy SHA-256"))
                                    .on_disabled_hover_text(if here {
                                        "A memory dump is a folder of files"
                                    } else {
                                        why
                                    })
                                    .clicked()
                                {
                                    copy_sha256(ui.ctx(), output.path.clone());
                                    ui.close_menu();
                                }
                                super::super::notes::menu_item(ui, || output.reference());
                            });
                        },
                    );
                });
        });
    });
    act
}

/// Copy a file's SHA-256 once it is read (on a thread: dumps are large).
fn copy_sha256(ctx: &egui::Context, path: PathBuf) {
    let ctx = ctx.clone();
    let _ = std::thread::Builder::new()
        .name("sample-artifact-hash".into())
        .spawn(move || {
            if let Some(hash) = antinomie_monitor_core::samples::file_sha256(&path) {
                ctx.copy_text(hash);
            }
            ctx.request_repaint();
        });
}

impl Kind {
    pub(in crate::app::samples_page) fn target(self) -> Option<crate::workspace::Panel> {
        self.panel()
    }
}
