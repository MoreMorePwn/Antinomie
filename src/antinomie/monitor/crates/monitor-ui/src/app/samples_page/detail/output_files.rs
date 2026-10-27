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
pub(super) enum Kind {
    Memory,
    Core,
    Capture,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Memory => "Memory dump",
            Kind::Core => "Core dump",
            Kind::Capture => "Network capture",
        }
    }

    fn open_label(self) -> &'static str {
        match self {
            Kind::Memory => "Open in Memory",
            Kind::Core => "Open in Core dumps",
            Kind::Capture => "Open in Network",
        }
    }

    fn panel(self) -> crate::workspace::Panel {
        match self {
            Kind::Memory => crate::workspace::Panel::Memory,
            Kind::Core => crate::workspace::Panel::CoreDump,
            Kind::Capture => crate::workspace::Panel::Network,
        }
    }
}

/// Where a file is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Availability {
    /// In the run's folder.
    InRun,
    /// Deleted through the app.
    Deleted,
    /// Not there, and not deleted through the app.
    Missing,
}

pub(super) struct Output {
    pub(super) number: usize,
    pub(super) kind: Kind,
    pub(super) path: PathBuf,
    pub(super) size: Option<u64>,
    pub(super) saved_because: &'static str,
    pub(super) availability: Availability,
    /// The state the run recorded ("Complete", "Partial" ...).
    pub(super) state: String,
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
        saved_because: because,
        state: state.to_owned(),
    }
}

/// Every output file of the runs, newest run first.
pub(super) fn read(entries: &[RunEntry]) -> Vec<Output> {
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
    out
}

/// What a click in the table asks for.
pub(super) enum Act {
    Open(usize, Kind),
    GoToRun(usize),
}

/// Draw the section; returns what was clicked.
pub(super) fn section(ui: &mut egui::Ui, data: &Data, font: f32) -> Option<Act> {
    let mut act = None;
    let present = data
        .outputs
        .iter()
        .filter(|output| output.availability == Availability::InRun)
        .count();
    parts::section(ui, "Output files", Some(present), |ui| {
        if data.outputs.is_empty() {
            parts::muted_line(ui, "None.");
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for kind in [Kind::Memory, Kind::Core, Kind::Capture] {
                let here = data
                    .outputs
                    .iter()
                    .filter(|o| o.kind == kind && o.availability == Availability::InRun)
                    .count();
                let gone = data
                    .outputs
                    .iter()
                    .filter(|o| o.kind == kind && o.availability != Availability::InRun)
                    .count();
                if here + gone == 0 {
                    continue;
                }
                ui.label(RichText::new(here.to_string()).strong());
                ui.label(format!(
                    "{}{}",
                    kind.label().to_lowercase(),
                    if here == 1 { "" } else { "s" }
                ));
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
        let because = widest("Saved because", &|output| output.saved_because.to_owned());
        let size = widest("Size", &|output| {
            output.size.map_or("–".to_owned(), crate::values::file_size)
        });
        // The three buttons need about this much; a narrower last column
        // puts them on two lines, in taller rows, instead of cutting them.
        let fixed = file + 70.0 + because + size + 140.0 + ui.spacing().item_spacing.x * 5.0;
        let roomy = ui.available_width() - fixed >= ACTIONS_WIDTH;
        parts::mini_table(ui, "sample_summary_outputs")
            .column(egui_extras::Column::exact(file))
            .column(egui_extras::Column::exact(70.0))
            .column(egui_extras::Column::exact(because))
            .column(egui_extras::Column::exact(size))
            .column(egui_extras::Column::exact(140.0))
            .column(egui_extras::Column::remainder().at_least(60.0))
            .header(table::header_height(font), |mut header| {
                for title in ["File", "Run", "Saved because", "Size", "Availability", ""] {
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
                        row.col(|ui| {
                            ui.label(output.kind.label());
                        });
                        row.col(|ui| {
                            ui.label(parts::run_name(output.number));
                        });
                        row.col(|ui| {
                            ui.label(output.saved_because);
                        });
                        row.col(|ui| {
                            ui.label(output.size.map_or("–".to_owned(), crate::values::file_size));
                        });
                        row.col(|ui| {
                            ui.horizontal(|ui| match output.availability {
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
                                    widgets::chip(ui, "Deleted by you", Tone::Neutral);
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
                                    _ => "The file is missing",
                                };
                                if ui
                                    .add_enabled(
                                        here,
                                        egui::Button::new(output.kind.open_label()).small(),
                                    )
                                    .on_disabled_hover_text(why)
                                    .clicked()
                                {
                                    act = Some(Act::Open(output.number, output.kind));
                                }
                                if ui.add(egui::Button::new("Go to run").small()).clicked() {
                                    act = Some(Act::GoToRun(output.number));
                                }
                                if ui
                                    .add_enabled(here, egui::Button::new("Open folder").small())
                                    .on_disabled_hover_text(why)
                                    .clicked()
                                {
                                    crate::evidence::reveal(ui.ctx(), &output.path);
                                }
                            });
                        });
                    },
                );
            });
    });
    act
}

impl Kind {
    pub(super) fn target(self) -> crate::workspace::Panel {
        self.panel()
    }
}

impl Output {
    #[cfg(test)]
    pub(super) fn kind_label(&self) -> &'static str {
        self.kind.label()
    }
}
