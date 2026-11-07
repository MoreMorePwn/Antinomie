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
    if !status.is_empty() {
        ui.label(status.as_str());
    }
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
            *status = match bpf::write_export(&directory.join("bpf"), bytes, &note.identity) {
                Ok((binary, metadata)) => {
                    format!("Wrote {} and {}", binary.display(), metadata.display())
                }
                Err(error) => error,
            };
        }
    }
}
