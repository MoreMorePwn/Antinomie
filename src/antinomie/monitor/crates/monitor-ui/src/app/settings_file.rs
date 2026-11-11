// SPDX-License-Identifier: GPL-3.0-only
//! The window's side of `<data>/settings.json` (core `settings`): the settings
//! every front end shares are read from it at start and written to it with
//! the window's own settings. The first start that finds no file writes one
//! from what eframe stored, so no user's value is lost; an older window ignores
//! the file and keeps its own copy, which is written as before.
use super::*;
use antinomie_monitor_core::settings::{self, EngineSettings};
use std::path::Path;

impl Settings {
    /// The shared settings as the file holds them. The runtime-only members of
    /// the detection settings (rules root, the evidence key, partial scans) are
    /// not part of the file.
    pub(super) fn engine(&self) -> EngineSettings {
        let mut detection = self.triage_detection.clone();
        detection.rules_root.clear();
        detection.evidence_key.clear();
        detection.partial = false;
        EngineSettings {
            settings_version: settings::SETTINGS_VERSION,
            triage_detection: detection,
            quota_gib: self.quota_gib,
            shutdown_timeout_s: self.timeout,
            core_budget_mib: self.core_budget_mib,
            analysis_time_limit_minutes: self.analysis_time_limit_minutes,
            file_write_file_mib: self.file_write_file_mib,
            file_write_run_mib: self.file_write_run_mib,
            file_before_file_mib: self.file_before_file_mib,
            file_before_run_mib: self.file_before_run_mib,
            automatic_detection: self.automatic_detection,
            live_detection_minutes: self.live_detection_minutes,
            outbound_catalog: self.outbound_catalog,
            address_lookup: self.address_lookup,
            report_export: self.report_export.clone(),
            bundle: self.bundle.clone(),
            analysis_limits: self.analysis_limits,
            memory_online_symbols: self.memory_online_symbols,
            sample_hash_lookup: self.sample_hash_lookup,
            disks: self.disks.clone(),
            start: Some(self.start),
            extra: self.engine_extra.clone(),
        }
    }

    /// Take the shared settings from the file.
    pub(super) fn adopt(&mut self, file: EngineSettings) {
        let runtime = std::mem::take(&mut self.triage_detection);
        self.triage_detection = file.triage_detection;
        self.triage_detection.rules_root = runtime.rules_root;
        self.triage_detection.evidence_key = runtime.evidence_key;
        self.triage_detection.partial = runtime.partial;
        self.quota_gib = file.quota_gib;
        self.timeout = file.shutdown_timeout_s;
        self.core_budget_mib = file.core_budget_mib;
        self.analysis_time_limit_minutes = file.analysis_time_limit_minutes;
        self.file_write_file_mib = file.file_write_file_mib;
        self.file_write_run_mib = file.file_write_run_mib;
        self.file_before_file_mib = file.file_before_file_mib;
        self.file_before_run_mib = file.file_before_run_mib;
        self.automatic_detection = file.automatic_detection;
        self.live_detection_minutes = file.live_detection_minutes;
        self.outbound_catalog = file.outbound_catalog;
        self.address_lookup = file.address_lookup;
        self.report_export = file.report_export;
        self.bundle = file.bundle;
        self.analysis_limits = file.analysis_limits;
        self.memory_online_symbols = file.memory_online_symbols;
        self.sample_hash_lookup = file.sample_hash_lookup;
        self.disks = file.disks;
        // A file no front end wrote them to keeps the window's own.
        if let Some(start) = file.start {
            self.start = start;
        }
        self.engine_extra = file.extra;
    }
}

/// What the window knows about `settings.json`.
#[derive(Debug, Default)]
pub(super) struct SettingsFile {
    /// What the file held when it was last read or written.
    last: Option<EngineSettings>,
    /// The file exists and cannot be used: it is left untouched and the
    /// window's own copy is used for this session.
    pub error: Option<String>,
    /// There was no file: write one as soon as the window holds the data lock.
    migrate: bool,
}

impl SettingsFile {
    /// Read the file into `settings`. A missing file marks the migration; a
    /// corrupt one is remembered and never replaced.
    pub(super) fn open(data_dir: &Path, settings: &mut Settings) -> Self {
        match settings::load(data_dir) {
            Ok(Some(file)) => {
                settings.adopt(file.clone());
                Self {
                    last: Some(file),
                    ..Self::default()
                }
            }
            Ok(None) => Self {
                migrate: true,
                ..Self::default()
            },
            Err(error) => Self {
                error: Some(error),
                ..Self::default()
            },
        }
    }

    /// Write the shared settings when they differ from the file, if this
    /// process holds the data lock. Returns a message when a write failed.
    pub(super) fn persist(&mut self, data_dir: &Path, settings: &Settings) -> Option<String> {
        if self.error.is_some() || !settings::holds_data_lock(data_dir) {
            return None;
        }
        let now = settings.engine();
        if self.last.as_ref() == Some(&now) && !self.migrate {
            return None;
        }
        // The values are the window's own; validate here so an out-of-range
        // value from an old copy does not stop every later write silently.
        match settings::save(data_dir, &now) {
            Ok(()) => {
                self.last = Some(now);
                self.migrate = false;
                None
            }
            Err(error) => Some(format!("Could not write settings.json: {error}")),
        }
    }
}

impl MonitorApp {
    /// Write `settings.json` now (it is also written with the window's own
    /// settings), and tell the user once if that fails.
    pub(super) fn persist_engine_settings(&mut self) {
        self.settings.triage_detection = self.triage.detection_settings().clone();
        let holds = self.backend.is_some();
        if !holds {
            return;
        }
        if let Some(message) = self
            .settings_file
            .persist(&self.options.data_dir, &self.settings)
        {
            if self.settings_file_reported.as_deref() != Some(&message) {
                self.settings_file_reported = Some(message.clone());
                self.status_notice = Some((crate::activity::Level::Warn, message));
            }
        } else {
            self.settings_file_reported = None;
        }
    }
}
