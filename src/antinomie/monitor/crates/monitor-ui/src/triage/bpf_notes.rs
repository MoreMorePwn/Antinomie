// SPDX-License-Identifier: GPL-3.0-only
//! The eBPF section. The notes are read in `antinomie_triage::bpf_notes`.
use super::*;

pub(super) use antinomie_triage::bpf_notes::*;

pub fn bpf_view(ui: &mut egui::Ui, input: &TriageInput<'_>, indexed: Option<&[BpfNote]>) {
    let page_notes;
    let notes = if let Some(notes) = indexed {
        notes
    } else {
        page_notes = bpf_notes(input);
        page_notes.as_slice()
    };
    if notes.is_empty() {
        ui.colored_label(
            theme::muted(),
            "No bpf syscall, classic socket filter, or seccomp install was recorded.",
        );
        return;
    }
    let rows: Vec<_> = notes
        .iter()
        .map(|note| bpf_row(note, input.clock_anchor))
        .collect();
    table(
        ui,
        "triage-bpf",
        &["Time", "Observation", "Outcome", "Evidence"],
        &rows,
    );
}

pub fn bpf_detail(
    ui: &mut egui::Ui,
    note: &BpfNote,
    directory: Option<&Path>,
    status: &mut String,
    cx: &bpf_fields::Context,
) {
    ui.label(theme::bold(ui, &note.heading));
    if let Some(line) = &note.lifecycle {
        ui.label(line);
    }
    if let Some(call) = note.loaded_by {
        ui.label(format!(
            "Program loaded in call {call}; this is its attach."
        ));
    }
    if !note.attributes.is_empty() {
        ui.label(theme::bold(ui, "Attributes"));
        for line in &note.attributes {
            ui.add(egui::Label::new(RichText::new(line).monospace()).wrap());
        }
    }
    if note.translation.is_none() && note.dump.is_none() {
        ui.weak("The instruction image was not isolated.");
    }
    // The captured identity as labelled fields; the export's JSON is for the file.
    bpf_fields::show(ui, note, cx);
    // The export's hex dump, after its JSON line, unless the dump is shown already.
    let export_dump = note
        .export
        .as_deref()
        .and_then(|export| export.split_once('\n'))
        .map(|(_, dump)| dump.to_owned())
        .filter(|_| note.dump.is_none());
    for text in [&note.translation, &note.dump, &export_dump]
        .into_iter()
        .flatten()
    {
        ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
    }
    if let (Some(bytes), Some(directory)) = (&note.bytes, directory) {
        if ui.button("Export binary and JSON").clicked() {
            let name = |path: &Path| {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            *status = match bpf::export_once(&directory.join("bpf"), bytes, &note.identity) {
                Ok(bpf::Exported::Wrote(binary, metadata)) => {
                    crate::export_dirs::reported(ui.ctx(), "eBPF program and JSON", &binary);
                    format!("Wrote {} and {}", name(&binary), name(&metadata))
                }
                Ok(bpf::Exported::Already(binary, _)) => {
                    // The name is the capture's: the same capture is one export.
                    let text = format!(
                        "Already exported: {} in {}",
                        name(&binary),
                        binary
                            .parent()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default()
                    );
                    crate::activity::report(ui.ctx(), crate::activity::Level::Info, &text);
                    text
                }
                Err(error) => {
                    crate::activity::report(
                        ui.ctx(),
                        crate::activity::Level::Error,
                        format!("eBPF export failed: {error}"),
                    );
                    error
                }
            };
        }
        // Beside the button, where the person is looking.
        if !status.is_empty() {
            ui.add(egui::Label::new(status.as_str()).wrap());
        }
    }
}
