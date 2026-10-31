// SPDX-License-Identifier: GPL-3.0-only
//! Static analysis report windows.
use super::*;

impl MonitorApp {
    pub(super) fn analysis_report(
        &self,
        id: &str,
    ) -> Option<&antinomie_monitor_core::AnalysisReport> {
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .filter_map(|run| run.analysis.as_ref())
            .chain(&self.snapshot.analysis_reports)
            .find(|report| report.id == id)
            .or_else(|| self.analysis_windows.get(id))
    }

    pub(super) fn refresh_analysis_windows(&mut self) {
        for (id, current) in &mut self.analysis_windows {
            if let Some(report) = self
                .snapshot
                .runs
                .iter()
                .chain(&self.history)
                .filter_map(|run| run.analysis.as_ref())
                .chain(&self.snapshot.analysis_reports)
                .find(|report| &report.id == id)
            {
                if current != report {
                    current.clone_from(report);
                }
            }
        }
    }

    pub(super) fn fail_analysis_read(&mut self, view_key: &str, generation: u64, reason: &str) {
        if let Some(view) = self.analysis_views.get_mut(view_key) {
            if view.pending.is_some_and(|ticket| ticket.0 == generation) {
                view.pending = None;
                view.preview = Some(Err(reason.into()));
            }
        }
    }

    pub(super) fn analysis_labels(
        &self,
        ui: &egui::Ui,
        report: &antinomie_monitor_core::AnalysisReport,
    ) -> (String, String, String, Vec<String>) {
        let annotation = self
            .analysis_directory(&report.id)
            .and_then(|directory| crate::evidence::annotation(ui, &directory))
            .unwrap_or_else(|| antinomie_monitor_core::annotations::Annotation {
                name: String::new(),
                tags: Vec::new(),
            });
        (
            report.id.clone(),
            annotation.name,
            report.source_path.clone(),
            annotation.tags,
        )
    }

    pub(super) fn analysis_identities(
        &self,
        report_id: &str,
    ) -> Vec<(&'static str, crate::query::RowValue)> {
        use crate::query::RowValue as V;
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| {
                run.analysis
                    .as_ref()
                    .is_some_and(|report| report.id == report_id)
            })
            .map_or_else(Vec::new, |run| {
                vec![
                    ("vm.id", V::Text(run.vm_id.clone())),
                    ("boot.id", V::Text(run.boot_id.clone())),
                    ("run.id", V::Text(run.id.clone())),
                ]
            })
    }

    /// The run a report was made for, when it is a run's.
    fn run_of_report(&self, report_id: &str) -> Option<String> {
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| {
                run.analysis
                    .as_ref()
                    .is_some_and(|report| report.id == report_id)
            })
            .map(|run| run.id.clone())
    }

    /// The seconds each analysis tool may run when the Run program window and
    /// Settings ask for a limit of their own; none leaves each tool its own.
    pub(super) fn analysis_time_limit_seconds(&self) -> Option<u64> {
        antinomie_monitor_core::time_limit_seconds(self.settings.analysis_time_limit_minutes)
    }

    pub(super) fn analysis_directory(&self, report_id: &str) -> Option<PathBuf> {
        if let Some(run) = self.snapshot.runs.iter().chain(&self.history).find(|run| {
            run.analysis
                .as_ref()
                .is_some_and(|report| report.id == report_id)
        }) {
            return Some(run.directory.join("analysis"));
        }
        if let Some(directory) = self.analysis_directories.get(report_id) {
            return Some(directory.clone());
        }
        // The analysis of an unpacked layer lives in its packed file's folder.
        if let Some(layer) = self
            .analysis_report(report_id)
            .and_then(|r| r.layer.as_ref())
        {
            let (parent, index) = (layer.parent_id.clone(), layer.index);
            return self
                .analysis_directory(&parent)
                .map(|directory| directory.join("layers").join(index.to_string()));
        }
        if report_id.is_empty()
            || !report_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !self
                .snapshot
                .analysis_reports
                .iter()
                .any(|report| report.id == report_id)
        {
            return None;
        }
        let vm_id = self
            .snapshot
            .active_vm
            .as_ref()
            .or(self.selected.as_ref())?;
        self.snapshot
            .vm_locations
            .iter()
            .find(|location| &location.vm_id == vm_id)
            .map(|location| {
                location
                    .recording_directory
                    .join("analyses")
                    .join(report_id)
            })
    }

    pub(super) fn analysis_action(
        &mut self,
        view_key: &str,
        action: Option<crate::analysis::ReportAction>,
    ) {
        match action {
            Some(crate::analysis::ReportAction::Export {
                report_id,
                kind,
                format,
            }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs
                        .export(directory, report_id, kind, format);
                } else {
                    self.report_error("Retained result directory is unavailable".into());
                }
            }
            Some(crate::analysis::ReportAction::ShowDirectory { report_id }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs.reveal(directory);
                } else {
                    self.report_error("Retained result directory is unavailable".into());
                }
            }
            Some(crate::analysis::ReportAction::OpenGhidra { report_id }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs.open_ghidra(
                        directory,
                        report_id,
                        self.options.data_dir.join("tools"),
                    );
                } else {
                    self.report_error("Retained result directory is unavailable".into());
                }
            }
            Some(crate::analysis::ReportAction::Cancel(analysis_id)) => {
                self.send(Command::CancelAnalysis { analysis_id })
            }
            Some(crate::analysis::ReportAction::RunCheck { report_id, kind }) => {
                let Some(directory) = self.analysis_directory(&report_id) else {
                    self.report_error("Retained result directory is unavailable".into());
                    return;
                };
                let run_id = self.run_of_report(&report_id);
                self.send(Command::AnalyzeMore {
                    directory,
                    run_id,
                    checks: vec![kind],
                    time_limit_seconds: self.analysis_time_limit_seconds(),
                    limits: self.settings.analysis_limits,
                });
            }
            Some(crate::analysis::ReportAction::RunCheckLonger {
                report_id,
                kind,
                seconds,
            }) => {
                let Some(directory) = self.analysis_directory(&report_id) else {
                    self.report_error("Retained result directory is unavailable".into());
                    return;
                };
                let run_id = self.run_of_report(&report_id);
                self.send(Command::AnalyzeMore {
                    directory,
                    run_id,
                    checks: vec![kind],
                    time_limit_seconds: Some(seconds),
                    limits: self.settings.analysis_limits,
                });
            }
            Some(crate::analysis::ReportAction::OpenAnalysisSettings) => {
                self.settings_open = true;
                self.settings_page = settings_window::SettingsPage::AnalysisTools;
            }
            Some(crate::analysis::ReportAction::OpenAnalysisLimit(setting)) => {
                self.settings_open = true;
                self.settings_page = settings_window::SettingsPage::AnalysisTools;
                self.settings_focus = Some(setting);
            }
            Some(crate::analysis::ReportAction::ShowReport { report_id }) => {
                if self.analysis_report(&report_id).is_some() {
                    self.selected_analysis = Some(report_id);
                } else {
                    self.report_error("That analysis is no longer listed".into());
                }
            }
            Some(crate::analysis::ReportAction::ScanRegex { report_id }) => {
                let Some(directory) = self.analysis_directory(&report_id) else {
                    self.report_error("Retained result directory is unavailable".into());
                    return;
                };
                let title = self
                    .analysis_report(&report_id)
                    .map(|report| {
                        report
                            .source_path
                            .rsplit('/')
                            .next()
                            .unwrap_or("")
                            .to_owned()
                    })
                    .unwrap_or_default();
                if let Some(view) = self.analysis_views.get_mut(view_key) {
                    view.state.scan_regex(&report_id, title, directory);
                }
            }
            Some(crate::analysis::ReportAction::OpenAnalysisTools) => {
                self.open_library(crate::workspace::LibraryPage::Tools)
            }
            Some(crate::analysis::ReportAction::OpenTriageProperties) => {
                self.triage.show_properties();
                self.focus_panel = Some(crate::workspace::Panel::Triage);
            }
            Some(crate::analysis::ReportAction::OpenRun { run_id }) => {
                self.select_run(Some(run_id));
                self.focus_panel = Some(crate::workspace::Panel::RunHistory);
            }
            Some(crate::analysis::ReportAction::OpenSection { report_id, kind }) => {
                if let Err(reason) = self.open_analysis_section(report_id, kind) {
                    self.report_error(reason);
                }
            }
            Some(crate::analysis::ReportAction::ReadSpecimen {
                report_id,
                offset,
                data_len,
            }) => {
                let directory = self.analysis_directory(&report_id);
                let Some(view) = self.analysis_views.get_mut(view_key) else {
                    return;
                };
                if view.report_id.as_deref() != Some(&report_id) {
                    return;
                }
                view.preview = None;
                let Some(directory) = directory else {
                    view.pending = None;
                    view.preview = Some(Err("Retained specimen directory unavailable".into()));
                    return;
                };
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                let generation = self.analysis_generation;
                view.pending = Some((generation, offset, data_len));
                self.queue_archive(Request::Specimen {
                    view_key: view_key.into(),
                    generation,
                    directory,
                    report_id,
                    offset,
                    data_len,
                });
            }
            Some(crate::analysis::ReportAction::ReadListing {
                report_id,
                kind,
                start,
                query,
                sort,
            }) => {
                let directory = self.analysis_directory(&report_id);
                let report = self.analysis_report(&report_id).cloned();
                let Some(view) = self.analysis_views.get_mut(view_key) else {
                    return;
                };
                if view.report_id.as_deref() != Some(&report_id)
                    || view
                        .listing_pending
                        .as_ref()
                        .is_some_and(|(_, k, s, q, o)| {
                            *k == kind && *s == start && *q == query && *o == sort
                        })
                {
                    return;
                }
                let Some(directory) = directory else {
                    view.listing = Some(Err("Retained analysis directory unavailable".into()));
                    return;
                };
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                let generation = self.analysis_generation;
                view.listing_pending = Some((generation, kind, start, query.clone(), sort));
                let record_context = report
                    .as_ref()
                    .map(|report| view.state.record_context_for(report, kind))
                    .unwrap_or_default();
                self.queue_archive(Request::Listing {
                    view_key: view_key.into(),
                    generation,
                    directory,
                    report_id,
                    kind,
                    start,
                    query,
                    sort,
                    record_context,
                });
            }
            None => {}
        }
    }

    pub(super) fn open_analysis_section(
        &mut self,
        report_id: String,
        kind: antinomie_monitor_core::AnalysisKind,
    ) -> Result<(), String> {
        if !self.analysis_windows.contains_key(&report_id) {
            if self.analysis_windows.len() >= 8 {
                return Err("Eight analysis reports are open. Close a result window before opening another report.".into());
            }
            let report = self
                .analysis_report(&report_id)
                .ok_or("The retained analysis report is unavailable")?
                .clone();
            if let Some(directory) = self.analysis_directory(&report_id) {
                self.analysis_directories
                    .insert(report_id.clone(), directory);
            }
            self.analysis_windows.insert(report_id.clone(), report);
        }
        let request = (report_id, kind);
        if !self.pending_analysis_sections.contains(&request) {
            self.pending_analysis_sections.push(request);
        }
        Ok(())
    }

    /// Open a tab of a static report the sample window read from a run of any
    /// VM: the report is kept with its folder so the tab can read it.
    pub(super) fn open_sample_report(
        &mut self,
        report: &antinomie_monitor_core::AnalysisReport,
        analysis_directory: PathBuf,
        kind: antinomie_monitor_core::AnalysisKind,
    ) {
        if !self.analysis_windows.contains_key(&report.id) && self.analysis_windows.len() >= 8 {
            self.report_error(
                "Eight analysis reports are open. Close a result window before opening another report."
                    .into(),
            );
            return;
        }
        self.analysis_directories
            .insert(report.id.clone(), analysis_directory);
        self.analysis_windows
            .entry(report.id.clone())
            .or_insert_with(|| report.clone());
        if let Err(reason) = self.open_analysis_section(report.id.clone(), kind) {
            self.report_error(reason);
        }
    }

    pub(crate) fn take_analysis_sections(
        &mut self,
    ) -> Vec<(String, antinomie_monitor_core::AnalysisKind)> {
        std::mem::take(&mut self.pending_analysis_sections)
    }

    pub(crate) fn retain_analysis_windows(&mut self, ids: &[String]) {
        self.analysis_windows.retain(|id, _| {
            ids.contains(id)
                || self
                    .pending_analysis_sections
                    .iter()
                    .any(|(pending, _)| pending == id)
        });
        self.analysis_views.retain(|key, view| {
            key == "workspace"
                || view
                    .report_id
                    .as_ref()
                    .is_some_and(|id| self.analysis_windows.contains_key(id))
        });
        self.analysis_directories
            .retain(|id, _| self.analysis_windows.contains_key(id));
    }
}
