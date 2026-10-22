// SPDX-License-Identifier: GPL-3.0-only
//! Details of a selected process: its suspicious observations and the jumps
//! scoped to it. Each jump reuses a navigation the app already has.
use super::*;
use crate::widgets::{self, Tone};

/// Temp-data key the Trace filter of a "Filter Trace to this process" jump is
/// left under for the app.
pub(super) const TRACE_SCOPE: &str = "triage-trace-scope";

/// Observations listed in Details; the rest are in Suspicious activity.
const LISTED: usize = 12;

/// The Trace filter that shows one process: its task cookie when known.
pub(super) fn trace_filter(pid: u64, cookie: u64) -> String {
    if cookie != 0 {
        format!("process.cookie == {cookie}")
    } else {
        format!("process.pid == {pid}")
    }
}

pub(super) fn show(view: &mut TriageView, ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
    let Some(pid) = files::number(values, "process.pid") else {
        return;
    };
    let cookie = files::number(values, "process.cookie").unwrap_or(0);
    let mine = |values: &[(&str, RowValue)]| {
        files::number(values, "process.pid") == Some(pid)
            && files::number(values, "process.cookie").unwrap_or(0) == cookie
    };
    let total = files::number(values, "process.suspicious").unwrap_or(0);
    let listed: Vec<Finding> = view
        .scan
        .as_ref()
        .map(|scan| {
            scan.findings
                .iter()
                .filter(|finding| mine(&finding.values))
                .take(LISTED)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    ui.separator();
    ui.label(
        RichText::new("Suspicious observations")
            .strong()
            .color(theme::text()),
    );
    if total == 0 {
        ui.weak("None recorded for this process.");
    }
    for finding in &listed {
        ui.horizontal_wrapped(|ui| {
            let tone = if finding.cells[1].text == "high" {
                Tone::Error
            } else {
                Tone::Warn
            };
            widgets::chip(ui, finding.cells[1].text.clone(), tone);
            let rule = egui::Label::new(RichText::new(&finding.cells[0].text).monospace())
                .sense(egui::Sense::click());
            if ui
                .add(rule)
                .on_hover_text("Open the syscall in Trace")
                .clicked()
            {
                request_evidence_jump(ui.ctx(), &finding.values);
            }
            ui.colored_label(theme::muted(), &finding.cells[3].text);
        });
    }
    if total > listed.len() as u64 {
        ui.weak(format!(
            "{} more in Suspicious activity.",
            total - listed.len() as u64
        ));
    }
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .button("Filter Trace to this process")
            .on_hover_text("Show only this process's calls in Trace")
            .clicked()
        {
            ui.ctx().data_mut(|data| {
                data.insert_temp(egui::Id::new(TRACE_SCOPE), trace_filter(pid, cookie));
            });
        }
        if ui
            .button("Files it touched")
            .on_hover_text("Opened files, filtered to this PID")
            .clicked()
        {
            view.scope_to_pid(ui.ctx(), Section::Files, pid);
        }
        if ui
            .add_enabled(total > 0, egui::Button::new("Suspicious activity"))
            .on_hover_text("Suspicious activity, filtered to this PID")
            .clicked()
        {
            view.scope_to_pid(ui.ctx(), Section::Process, pid);
        }
    });
}

impl TriageView {
    /// Open `section`'s table (Files › Opened, or Process › Suspicious
    /// activity) filtered to one PID.
    fn scope_to_pid(&mut self, ctx: &egui::Context, section: Section, pid: u64) {
        self.section = section;
        let slot = if section == Section::Files {
            self.files = FileTab::Opened;
            FileTab::Opened.slot()
        } else {
            self.process = ProcessTab::Suspicious;
            0
        };
        let draft = format!("process.pid == {pid}");
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(("triage-filter-draft", slot)), draft));
    }
}
