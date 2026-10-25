// SPDX-License-Identifier: GPL-3.0-only
//! A bounded worker for exports and external native-project opening.
use antinomie_monitor_core::{AnalysisExportFormat, AnalysisKind};
use eframe::egui;
use std::{path::PathBuf, sync::mpsc};

struct Export {
    directory: PathBuf,
    report_id: String,
    kind: Option<AnalysisKind>,
    format: AnalysisExportFormat,
    destination: String,
    open_tools: Option<PathBuf>,
}
#[derive(Default)]
pub(crate) struct EvidenceJobs {
    export: Option<Export>,
    receiver: Option<mpsc::Receiver<Result<String, String>>>,
    result: Option<Result<String, String>>,
}
impl EvidenceJobs {
    pub(crate) fn reveal(&mut self, directory: PathBuf) {
        self.start(move || {
            crate::folders::show(&directory)?;
            Ok(format!("Opened {}", directory.display()))
        });
    }
    pub(crate) fn export(
        &mut self,
        directory: PathBuf,
        report_id: String,
        kind: Option<AnalysisKind>,
        format: AnalysisExportFormat,
    ) {
        if self.receiver.is_some() {
            self.result = Some(Err("An evidence action is already running".into()));
            return;
        }
        let suffix = match format {
            AnalysisExportFormat::Text => "txt",
            AnalysisExportFormat::Json => "json",
            AnalysisExportFormat::GhidraProject => "ghidra-project",
        };
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        let destination = home
            .join(format!(
                "antinomie-{}-{}.{}",
                report_id,
                kind.map(|k| format!("{k:?}"))
                    .unwrap_or_else(|| "report".into()),
                suffix
            ))
            .display()
            .to_string();
        self.export = Some(Export {
            directory,
            report_id,
            kind,
            format,
            destination,
            open_tools: None,
        });
        self.result = None;
    }
    pub(crate) fn open_ghidra(
        &mut self,
        directory: PathBuf,
        report_id: String,
        tools_directory: PathBuf,
    ) {
        if self.receiver.is_some() {
            self.result = Some(Err("An evidence action is already running".into()));
            return;
        }
        self.export(
            directory,
            report_id,
            Some(AnalysisKind::Decompilation),
            AnalysisExportFormat::GhidraProject,
        );
        if let Some(export) = &mut self.export {
            export.open_tools = Some(tools_directory);
        }
    }
    fn launch_project(project: PathBuf, tools_directory: PathBuf) -> Result<String, String> {
        let mut command =
            antinomie_monitor_core::ghidra_open_exported_project(&project, &tools_directory)?;
        let mut child = command.spawn().map_err(|e| format!("Open Ghidra: {e}"))?;
        // An immediately failed launcher is surfaced; a running GUI owns its lifetime.
        std::thread::sleep(std::time::Duration::from_millis(300));
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) if !status.success() => Err(format!("Ghidra launch failed: {status}")),
            Some(_) => Ok("Ghidra launcher completed".into()),
            None => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                Ok("Opened retained project in Ghidra".into())
            }
        }
    }
    fn start(&mut self, work: impl FnOnce() -> Result<String, String> + Send + 'static) {
        if self.receiver.is_some() {
            self.result = Some(Err("An evidence action is already running".into()));
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        match std::thread::Builder::new()
            .name("evidence-export".into())
            .spawn(move || {
                let _ = sender.send(work());
            }) {
            Ok(_) => {
                self.receiver = Some(receiver);
                self.result = None;
            }
            Err(e) => self.result = Some(Err(e.to_string())),
        }
    }
    pub(crate) fn show(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.receiver {
            match receiver.try_recv() {
                Ok(result) => {
                    self.receiver = None;
                    self.result = Some(result);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.receiver = None;
                    self.result = Some(Err(
                        "Evidence worker stopped before reporting its result".into()
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(export) = &mut self.export {
            let mut open = true;
            let mut save = false;
            crate::widgets::window("Export analysis result").open(&mut open).default_width(620.0).collapsible(false).show(ctx, |ui| {
                ui.label(if export.format == AnalysisExportFormat::GhidraProject { "Destination: new directory" } else { "Destination: new file" });
                ui.add(egui::TextEdit::singleline(&mut export.destination).desired_width(f32::INFINITY));
                save = ui.add_enabled(!export.destination.trim().is_empty(), egui::Button::new("Export"))
                    .on_hover_text("Exports all saved rows in this category, including rows outside the current page/filter. Existing files are preserved.")
                    .clicked();
            });
            if save {
                if let Some(export) = self.export.take() {
                    self.start(move || {
                        let path = antinomie_monitor_core::export_analysis(
                            &export.directory,
                            &export.report_id,
                            export.kind,
                            export.format,
                            &crate::folders::user_path(export.destination.trim()),
                        )?;
                        if let Some(tools) = export.open_tools {
                            Self::launch_project(path.join("antinomie.gpr"), tools)
                        } else {
                            Ok(format!("Exported {}", path.display()))
                        }
                    });
                }
            } else if !open {
                self.export = None;
            }
        }
        if self.receiver.is_some() || self.result.is_some() {
            let mut open = true;
            crate::widgets::window("Evidence action")
                .open(&mut open)
                .show(ctx, |ui| {
                    if self.receiver.is_some() {
                        crate::theme::loading(ui, "Working…");
                    }
                    if let Some(result) = &self.result {
                        match result {
                            Ok(text) => {
                                ui.label(text);
                            }
                            Err(error) => {
                                crate::activity::error_toast(ui, error);
                            }
                        }
                    }
                });
            if !open {
                self.result = None;
            }
        }
    }
}
