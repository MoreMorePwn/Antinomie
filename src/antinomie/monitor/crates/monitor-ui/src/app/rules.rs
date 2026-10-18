// SPDX-License-Identifier: MIT
//! Local rule state belongs to application startup, independently of its window.
use super::*;

impl MonitorApp {
    pub(super) fn configure_detection(&mut self) {
        *self.triage.detection_settings() = self.settings.triage_detection.clone();
        self.triage.set_rules(
            &self.options.data_dir,
            self.settings.automatic_detection,
            &self.rules_summary,
            self.rules_generation,
        );
    }

    pub(super) fn poll_rules(&mut self, ctx: &egui::Context) {
        self.rules_ui.tick(ctx, &self.options.data_dir);
        let changed = self.rules_ui.changed();
        if changed {
            self.rules_generation = self.rules_generation.saturating_add(1);
        }
        if changed || self.rules_summary.is_empty() {
            self.rules_summary = self.rules_ui.profile();
        }
        // Persisted settings omit the machine-local root. Bind it before the
        // first detector tick to prevent unmanaged/empty startup scans.
        self.configure_detection();
    }
}
