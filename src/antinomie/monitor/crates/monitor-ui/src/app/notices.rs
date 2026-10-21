// SPDX-License-Identifier: MIT
//! Observe backend diagnostic state even when its owning panel is closed.
//!
//! The backend's own errors and warnings are toasts. What belongs to one run,
//! core or capture is logged to Activity only; its view shows it inline.
use super::*;
use crate::activity::{report, report_quiet, Level};

impl MonitorApp {
    pub(super) fn collect_notices(&self, ctx: &egui::Context) {
        let snapshot = &self.snapshot;
        // A condition that stands is one toast; it toasts again only after it
        // has gone and come back.
        let key = egui::Id::new("collected-notices");
        let previous: std::collections::HashSet<String> =
            ctx.data(|data| data.get_temp(key)).unwrap_or_default();
        let mut now = std::collections::HashSet::new();
        let mut emit = |level: Level, message: String| {
            if !previous.contains(&message) {
                report(ctx, level, &message);
            }
            now.insert(message);
        };
        for message in crate::summary::health::notices(snapshot, &self.history) {
            emit(Level::Warn, message.to_string());
        }
        for error in [
            &snapshot.last_error,
            &snapshot.health.persistence_error,
            &snapshot.remote_error,
            &self.archive_error,
            &self.run_query_error,
        ]
        .into_iter()
        .flatten()
        {
            emit(Level::Error, error.to_string());
        }
        for error in [
            snapshot
                .download
                .as_ref()
                .and_then(|value| value.error.as_ref()),
            snapshot
                .build
                .as_ref()
                .and_then(|value| value.error.as_ref()),
            snapshot
                .tool_install
                .as_ref()
                .and_then(|value| value.error.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            emit(Level::Error, error.to_string());
        }
        if let Some(resources) = &snapshot.vm_resources {
            for error in [
                resources.sample_error.as_ref(),
                resources
                    .guest
                    .as_ref()
                    .and_then(|guest| guest.error.as_ref()),
            ]
            .into_iter()
            .flatten()
            {
                emit(Level::Warn, error.to_string());
            }
        }
        if let Some(flush) = &snapshot.recording_flush {
            for error in &flush.errors {
                emit(Level::Error, error.to_string());
            }
        }
        ctx.data_mut(|data| data.insert_temp(key, now));
        for run in snapshot.runs.iter().chain(&self.history) {
            if let Some(message) = crate::run_recording::warning_message(run) {
                report_quiet(ctx, Level::Warn, message);
            }
            if let Some(analysis) = &run.analysis {
                if let Some(reason) = &analysis.reason {
                    report_quiet(ctx, Level::Warn, reason);
                }
            }
        }
        for core in &snapshot.process_cores {
            if let Some(issue) = &core.issue {
                report_quiet(ctx, Level::Warn, issue);
            }
        }
        for capture in snapshot.captures.iter().chain(&self.capture_history) {
            if let Some(error) = &capture.recording_error {
                report_quiet(ctx, Level::Warn, error);
            }
            if let Some(reason) = &capture.incomplete_reason {
                report_quiet(ctx, Level::Warn, reason);
            }
        }
        for report_value in snapshot
            .analysis_reports
            .iter()
            .chain(self.analysis_windows.values())
        {
            if let Some(reason) = &report_value.reason {
                report_quiet(ctx, Level::Warn, reason);
            }
        }
    }
}
