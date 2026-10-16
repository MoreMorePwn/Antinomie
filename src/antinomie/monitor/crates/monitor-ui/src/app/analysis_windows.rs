// SPDX-License-Identifier: MIT
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
                    self.status = "Retained result directory is unavailable".into();
                }
            }
            Some(crate::analysis::ReportAction::ShowDirectory { report_id }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs.reveal(directory);
                } else {
                    self.status = "Retained result directory is unavailable".into();
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
                    self.status = "Retained result directory is unavailable".into();
                }
            }
            Some(crate::analysis::ReportAction::Cancel(analysis_id)) => {
                self.send(Command::CancelAnalysis { analysis_id })
            }
            Some(crate::analysis::ReportAction::OpenAnalysisTools) => self.tools_open = true,
            Some(crate::analysis::ReportAction::OpenSection { report_id, kind }) => {
                if let Err(reason) = self.open_analysis_section(report_id, kind) {
                    self.status = reason;
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
                        .is_some_and(|(_, k, s, q)| *k == kind && *s == start && *q == query)
                {
                    return;
                }
                let Some(directory) = directory else {
                    view.listing = Some(Err("Retained analysis directory unavailable".into()));
                    return;
                };
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                let generation = self.analysis_generation;
                view.listing_pending = Some((generation, kind, start, query.clone()));
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
