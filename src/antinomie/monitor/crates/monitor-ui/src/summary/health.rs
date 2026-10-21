// SPDX-License-Identifier: MIT
//! Capture-loss scopes stay separate: recorder sends, transport, UI, storage and runs.
use crate::{activity, theme};
use antinomie_monitor_core::{Health, RunSummary, Snapshot};
use eframe::egui::{self, Color32};
use std::collections::HashSet;

pub(super) struct Facts<'a> {
    failed_sends: Option<u64>,
    async_runs: Vec<&'a RunSummary>,
}

impl<'a> Facts<'a> {
    pub(super) fn new(snapshot: &'a Snapshot, history: &'a [RunSummary]) -> Self {
        let mut seen = HashSet::new();
        let async_runs = snapshot
            .runs
            .iter()
            .chain(history)
            .filter(|run| {
                snapshot.active_vm.as_deref() == Some(run.vm_id.as_str())
                    && snapshot.boot_id.as_deref() == Some(run.boot_id.as_str())
                    && run.has_async_loss()
                    && seen.insert(run.id.as_str())
            })
            .collect();
        Self {
            failed_sends: snapshot.health.recorder_stats.map(|stats| stats[6]),
            async_runs,
        }
    }

    pub(super) fn state(&self, health: &Health) -> (&'static str, Color32) {
        if health.persistence_error.is_some() {
            ("Recording error", theme::error())
        } else if health.dropped > 0
            || health.ui_dropped > 0
            || health.storage_dropped_packets > 0
            || health.guest_note_lost > 0
            || health.shedding
            || self.failed_sends.is_some_and(|count| count > 0)
            || !self.async_runs.is_empty()
        {
            ("Loss observed", theme::warn())
        } else if health.recorder_stats_error.is_some() {
            ("Recorder health unavailable", theme::warn())
        } else if self.failed_sends.is_none() {
            ("Recorder health pending", theme::muted())
        } else {
            ("No recorded losses", theme::good())
        }
    }

    pub(super) fn show(&self, ui: &mut egui::Ui, snapshot: &Snapshot) {
        ui.horizontal_wrapped(|ui| {
            ui.label(if snapshot.health.recorder_stats_error.is_some() {
                "Last recorder failed sends"
            } else {
                "Recorder failed sends"
            });
            ui.monospace(
                self.failed_sends
                    .map_or_else(|| "Unavailable".into(), |count| count.to_string()),
            );
            ui.colored_label(
                theme::muted(),
                "Boot cumulative; may overlap transport drops",
            );
        });
        ui.horizontal_wrapped(|ui| {
            ui.label("Runs with async observation loss (this boot)");
            ui.monospace(self.async_runs.len().to_string());
        });
        for run in self.async_runs.iter().take(6) {
            if let Some(status) = &run.execution {
                ui.add(
                    egui::Label::new(format!(
                        "{} [{}]: {} async observations lost",
                        run.request.path,
                        short_id(&run.id),
                        status.async_loss_count,
                    ))
                    .wrap(),
                );
            } else {
                ui.add(egui::Label::new(format!("{} [{}]: async loss retained in run notes; current execution status unavailable", run.request.path, short_id(&run.id))).wrap());
            }
        }
        if self.async_runs.len() > 6 {
            ui.label(format!(
                "{} more affected runs; open Run History for their execution status",
                self.async_runs.len() - 6
            ));
        }
        for message in self.messages(snapshot).take(8) {
            activity::warning(ui, message);
        }
    }

    fn messages<'b>(&'b self, snapshot: &'b Snapshot) -> impl Iterator<Item = String> + 'b {
        let boot = snapshot
            .boot_id
            .as_deref()
            .map(short_id)
            .unwrap_or_else(|| "unknown".into());
        let recorder = self.failed_sends.filter(|count| *count > 0).map(|_| format!("Recorder capture loss reported for boot {boot}; failed sends are separate from TRL, UIL and STL."));
        let unavailable = snapshot
            .health
            .recorder_stats_error
            .as_ref()
            .map(|error| format!("Recorder health unavailable for boot {boot}: {error}"));
        [recorder, unavailable].into_iter().flatten().chain(self.async_runs.iter().map(move |run| {
            format!("Async observations lost for {} [{}], boot {boot}; see the retained run notes and execution status.", run.request.path, short_id(&run.id))
        }))
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Stable messages deduplicate repeated polls and counters that keep increasing.
pub(crate) fn notices(snapshot: &Snapshot, history: &[RunSummary]) -> Vec<String> {
    let facts = Facts::new(snapshot, history);
    facts.messages(snapshot).collect()
}

pub(super) fn details(ui: &mut egui::Ui, health: &Health) {
    for (label, value) in [
        ("Packets persisted", health.persisted_packets.to_string()),
        ("Write backlog", super::size(health.write_backlog)),
        ("Parser errors", health.parser_errors.to_string()),
        ("Reply stalls", health.reply_stalls.to_string()),
    ] {
        ui.horizontal_wrapped(|ui| {
            ui.label(label);
            ui.monospace(value);
        });
    }
    if let Some(stats) = health.recorder_stats {
        ui.add(
            egui::Label::new(format!(
                "Copy faults: {} · schema gaps: {} · context failures: {}",
                stats[7], stats[8], stats[9]
            ))
            .wrap(),
        )
        .on_hover_text("Observation diagnostics are not added to the packet-drop counters.");
    }
}

#[cfg(test)]
mod tests;
