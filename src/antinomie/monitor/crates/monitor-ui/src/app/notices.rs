// SPDX-License-Identifier: MIT
//! Observe backend diagnostic state even when its owning panel is closed.
use super::*;
use crate::activity::{report, Level};

impl MonitorApp {
    pub(super) fn collect_notices(&self, ctx: &egui::Context) {
        let snapshot = &self.snapshot;
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
            report(ctx, Level::Error, error);
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
            report(ctx, Level::Error, error);
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
                report(ctx, Level::Warn, error);
            }
        }
        if let Some(flush) = &snapshot.recording_flush {
            for error in &flush.errors {
                report(ctx, Level::Error, error);
            }
        }
        for run in snapshot.runs.iter().chain(&self.history) {
            if let Some(error) = &run.recording_error {
                report(
                    ctx,
                    Level::Warn,
                    format!("Recording incomplete: saving stopped: {error}"),
                );
            }
            if let Some(analysis) = &run.analysis {
                if let Some(reason) = &analysis.reason {
                    report(ctx, Level::Warn, reason);
                }
            }
        }
        for core in &snapshot.process_cores {
            if let Some(issue) = &core.issue {
                report(ctx, Level::Warn, issue);
            }
        }
        for capture in snapshot.captures.iter().chain(&self.capture_history) {
            if let Some(error) = &capture.recording_error {
                report(ctx, Level::Warn, error);
            }
            if let Some(reason) = &capture.incomplete_reason {
                report(ctx, Level::Warn, reason);
            }
        }
        for report_value in snapshot
            .analysis_reports
            .iter()
            .chain(self.analysis_windows.values())
        {
            if let Some(reason) = &report_value.reason {
                report(ctx, Level::Warn, reason);
            }
        }
    }
}
