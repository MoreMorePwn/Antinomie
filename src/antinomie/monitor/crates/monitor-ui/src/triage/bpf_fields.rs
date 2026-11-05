// SPDX-License-Identifier: GPL-3.0-only
//! The identity of a captured BPF image as labelled fields, not as the JSON
//! the export file holds: what happened, to which program, who did it and
//! when, with the recording's own ids folded away.
use super::*;
use crate::bpf::BpfIdentity;

/// One labelled value of the view; `hover` says more of it.
pub(super) struct Field {
    pub label: &'static str,
    pub value: String,
    pub hover: Option<String>,
}

fn field(label: &'static str, value: impl Into<String>) -> Field {
    Field {
        label,
        value: value.into(),
        hover: None,
    }
}

/// What the view reads besides the identity: the program's name, the start
/// of the run and the host clock.
pub(super) struct Context {
    pub image: Option<String>,
    pub start: Option<u64>,
    pub clock: Option<antinomie_monitor_core::HostClockAnchor>,
}

/// The context of `note` in `scan`: the name of the process that made the call.
pub(super) fn context(
    scan: &ArchiveScan,
    note: &BpfNote,
    fallback: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Context {
    let image = scan
        .process
        .iter()
        .find(|node| {
            note.identity.cookie == Some(node.cookie)
                || note.identity.pid == Some(node.pid) && node.tid == node.pid
        })
        .map(|node| node.comm.clone());
    Context {
        image,
        start: file_tabs::run_start(scan),
        clock: scan.clock_anchor.or(fallback),
    }
}

/// The fields shown at the top; null ones are left out.
pub(super) fn fields(identity: &BpfIdentity, bytes: Option<&[u8]>, cx: &Context) -> Vec<Field> {
    let mut out = vec![field("Action", &identity.action)];
    if !identity.attachment_kind.is_empty() {
        out.push(field("Attachment", &identity.attachment_kind));
    }
    if !identity.source_syscall.is_empty() {
        out.push(field("Source syscall", &identity.source_syscall));
    }
    if let Some(pid) = identity.pid {
        let tid = identity.tid.unwrap_or(pid);
        out.push(field(
            "Process",
            process_cells::task_label(pid, tid, cx.image.as_deref()),
        ));
    }
    if let Some(ns) = identity.timestamp_ns {
        let mut time = field("Time", process_cells::relative(Some(ns), cx.start));
        time.hover = Some(crate::time_format::guest_ns(cx.clock, Some(ns)));
        out.push(time);
    }
    if let Some(result) = identity.result {
        out.push(field("Result", result.to_string()));
    }
    if let Some(bytes) = bytes {
        let complete = bytes.len() / 8;
        out.push(field(
            "Instructions",
            match identity.declared_instruction_count {
                Some(declared) => format!("{complete} captured of {declared} declared"),
                None => complete.to_string(),
            },
        ));
        out.push(field("Captured bytes", bytes.len().to_string()));
        let partial = !bytes.len().is_multiple_of(8)
            || identity
                .declared_instruction_count
                .is_some_and(|declared| declared > complete as u64)
            || !identity.capture_issues.is_empty();
        out.push(field("Partial", if partial { "yes" } else { "no" }));
        out.push(field("Padded", "no"));
    }
    if let Some(id) = identity.program_id {
        out.push(field("Program id", id.to_string()));
    }
    if let Some(fd) = identity.fd {
        out.push(field("fd", fd.to_string()));
    }
    out
}

/// The ids of the recording, for the fold: they name where the call is
/// stored and mean nothing to the program.
pub(super) fn recording_ids(identity: &BpfIdentity) -> Vec<Field> {
    let mut out = Vec::new();
    for (label, value) in [
        ("VM", identity.vm_id.clone()),
        ("Boot", identity.boot_id.clone()),
        ("Run", identity.run_id.clone()),
        (
            "Task cookie",
            identity.cookie.map(|cookie| cookie.to_string()),
        ),
        ("Stream", Some(identity.stream_id.to_string())),
        ("Event", identity.event_id.map(|id| id.to_string())),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            out.push(field(label, value));
        }
    }
    out
}

/// The SHA-256 of the captured bytes, cut to twelve digits.
pub(super) fn digest(bytes: &[u8]) -> (String, String) {
    let full = antinomie_monitor_core::storage::sha256_hex(bytes);
    (file_shown::short_hash(&full), full)
}

/// Draw the fields of `note`: the labelled values, the digest with its copy
/// button, the capture issues and the folded recording ids.
pub(super) fn show(ui: &mut egui::Ui, note: &BpfNote, cx: &Context) {
    egui::Grid::new("triage-bpf-fields")
        .num_columns(2)
        .spacing(egui::vec2(14.0, 6.0))
        .show(ui, |ui| {
            let rows = fields(&note.identity, note.bytes.as_deref(), cx);
            for field in &rows {
                ui.label(RichText::new(field.label).small().color(theme::muted()));
                let value = ui.label(&field.value);
                if let Some(hover) = &field.hover {
                    value.on_hover_text(hover);
                }
                ui.end_row();
            }
            if let Some(bytes) = note.bytes.as_deref() {
                let (short, full) = digest(bytes);
                ui.label(RichText::new("SHA-256").small().color(theme::muted()));
                ui.horizontal(|ui| {
                    ui.label(RichText::new(short).monospace())
                        .on_hover_text(&full);
                    if ui
                        .small_button("Copy")
                        .on_hover_text("Copy the whole digest")
                        .clicked()
                    {
                        ui.ctx().copy_text(full);
                    }
                });
                ui.end_row();
            }
        });
    if !note.identity.capture_issues.is_empty() {
        ui.add_space(6.0);
        ui.label(theme::bold(ui, "Capture issues"));
        for issue in &note.identity.capture_issues {
            ui.add(egui::Label::new(format!("\u{2022} {issue}")).wrap());
        }
    }
    let ids = recording_ids(&note.identity);
    if !ids.is_empty() {
        ui.add_space(6.0);
        egui::CollapsingHeader::new("Recording ids")
            .id_salt("triage-bpf-recording-ids")
            .default_open(false)
            .show(ui, |ui| {
                egui::Grid::new("triage-bpf-ids")
                    .num_columns(2)
                    .spacing(egui::vec2(14.0, 4.0))
                    .show(ui, |ui| {
                        for field in &ids {
                            ui.label(RichText::new(field.label).small().color(theme::muted()));
                            ui.label(RichText::new(&field.value).monospace());
                            ui.end_row();
                        }
                    });
            });
    }
}

#[cfg(test)]
mod tests;
