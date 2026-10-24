// SPDX-License-Identifier: GPL-3.0-only
//! MemNixFS beside Volatility: the backend tabs, the tool's state and the
//! report picker. A report is run like a plugin and saved with the dump; its
//! result is shown by the same table, filters, messages and Files button.
use super::*;
use antinomie_monitor_core::memory::memnixfs::{self, MemNixFs, Report};

/// MemNixFS's availability: located (and able to start) on a worker thread.
pub(super) enum Engine {
    Unknown,
    Loading(Receiver<Result<MemNixFs, String>>),
    Ready(MemNixFs),
    Failed(String),
}

impl MemoryView {
    /// MemNixFS was installed or removed: look for it again.
    pub(super) fn check_engine(&mut self, installed: bool) {
        let ready = matches!(self.engine, Engine::Ready(_));
        let failed = matches!(self.engine, Engine::Failed(_));
        if (installed && failed) || (!installed && ready) {
            self.engine = Engine::Unknown;
        }
    }

    /// Start locating MemNixFS when it is wanted, and take the answer.
    pub(super) fn poll_engine(&mut self, data_dir: &Path) {
        if let Engine::Loading(receiver) = &self.engine
            && let Ok(located) = receiver.try_recv()
        {
            self.engine = match located {
                Ok(tool) => Engine::Ready(tool),
                Err(error) => Engine::Failed(error),
            };
        }
        if self.analyzer == Analyzer::MemNixFs && matches!(self.engine, Engine::Unknown) {
            let (sender, receiver) = mpsc::channel();
            let data_dir = data_dir.to_path_buf();
            std::thread::spawn(move || {
                let _ = sender.send(MemNixFs::locate(&data_dir));
            });
            self.engine = Engine::Loading(receiver);
        }
    }

    /// Volatility 3 or MemNixFS: which one the next Run uses.
    pub(super) fn analyzer_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Analyse with").color(theme::muted()));
            for analyzer in Analyzer::ALL {
                let item = crate::widgets::TabItem::new(analyzer.product());
                if crate::widgets::tab(ui, self.analyzer == analyzer, &item)
                    .on_hover_text(match analyzer {
                        Analyzer::Volatility => {
                            "Volatility 3 plugins: any system, the broadest set of checks"
                        }
                        Analyzer::MemNixFs => {
                            "MemNixFS: Linux dumps only. Reads the kernel's structures into \
                             reports (processes, sockets, findings, timeline) and recovers \
                             files from the page cache, offline in the analysis sandbox"
                        }
                    })
                    .clicked()
                {
                    self.analyzer = analyzer;
                }
            }
        });
    }

    /// While MemNixFS is chosen: that it is loading, or why it cannot run.
    pub(super) fn engine_banner(
        &mut self,
        ui: &mut egui::Ui,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let mut action = None;
        match &self.engine {
            Engine::Ready(_) => {}
            Engine::Unknown | Engine::Loading(_) => {
                theme::loading_colored(ui, theme::muted(), "Checking MemNixFS…");
            }
            Engine::Failed(error) => {
                let error = error.clone();
                egui::Frame::new()
                    .fill(theme::raised())
                    .corner_radius(4.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            crate::activity::error(ui, &error);
                            if cx.memnixfs_installed {
                                if ui.button("Try again").clicked() {
                                    self.engine = Engine::Unknown;
                                }
                            } else if cx.memnixfs_installing {
                                theme::loading(ui, "Installing MemNixFS…");
                            } else {
                                ui.label(
                                    "MemNixFS reads Linux memory dumps. Install it once \
                                     (about 2.4 MB, pinned release):",
                                );
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Install MemNixFS")
                                                .color(theme::palette().primary_text),
                                        )
                                        .fill(theme::primary()),
                                    )
                                    .clicked()
                                {
                                    action = Some(MemoryAction::InstallMemNixFs);
                                }
                            }
                        });
                    });
            }
        }
        action
    }

    /// The report picker and Run button.
    pub(super) fn report_bar(&mut self, ui: &mut egui::Ui, dump: &MemoryDump, font_size: f32) {
        let Engine::Ready(tool) = &self.engine else {
            return;
        };
        let current = self
            .report
            .as_deref()
            .and_then(memnixfs::report)
            .unwrap_or(&memnixfs::REPORTS[0]);
        let mut chosen = None;
        let mut run = false;
        let linux = dump.os == Os::Linux;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Report").color(theme::muted()));
            egui::ComboBox::from_id_salt("memnixfs_report")
                .width(260.0)
                .height(480.0)
                .selected_text(RichText::new(current.name).font(theme::mono(font_size - 1.0)))
                .show_ui(ui, |ui| {
                    let mut area = "";
                    for report in memnixfs::REPORTS {
                        if report.area != area {
                            area = report.area;
                            ui.add_space(2.0);
                            ui.label(RichText::new(area).small().color(theme::heading()));
                        }
                        if ui
                            .selectable_label(
                                report.name == current.name,
                                RichText::new(report.name).font(theme::mono(font_size - 1.0)),
                            )
                            .on_hover_text(report.help)
                            .clicked()
                        {
                            chosen = Some(report.name.to_owned());
                        }
                    }
                });
            let plugin = current.plugin();
            let running = self
                .jobs
                .iter()
                .any(|job| job.run.dump_id == dump.id && job.run.plugin == plugin);
            if ui
                .add_enabled(
                    !running && linux,
                    egui::Button::new(
                        RichText::new(format!("{} Run", egui_phosphor::regular::PLAY))
                            .color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
                .on_hover_text("Run the report on this dump; the result is saved with it")
                .on_disabled_hover_text(if linux {
                    "This report is already running on this dump"
                } else {
                    "MemNixFS reads Linux dumps only"
                })
                .clicked()
            {
                run = true;
            }
            ui.menu_button(egui_phosphor::regular::GEAR, |ui| {
                ui.set_max_width(440.0);
                ui.label(
                    RichText::new(
                        "MemNixFS runs offline in the analysis sandbox: it sees only this dump \
                         and its saved symbol table, has no network and writes only the \
                         result. It takes about a minute to read a dump. Only dumps of the \
                         whole guest's physical memory are accepted (QEMU ELF cores, LiME, \
                         AVML, kdump, raw images); a process core is refused. Without a saved \
                         symbol table it rebuilds one from the kernel's own BTF.",
                    )
                    .color(theme::muted()),
                );
                ui.add_space(4.0);
                ui.label(format!("MemNixFS {}", tool.version));
            })
            .response
            .on_hover_text("About MemNixFS");
            ui.add(egui::Label::new(RichText::new(current.help).color(theme::muted())).truncate())
                .on_hover_text(current.help);
        });
        if !linux {
            crate::activity::warning(
                ui,
                format!(
                    "This dump is {}: MemNixFS reads Linux dumps only",
                    dump.os.label()
                ),
            );
        } else if !dump.symbols {
            ui.colored_label(
                theme::muted(),
                "No symbol table is saved with this dump: MemNixFS rebuilds what it needs from \
                 the kernel's BTF, and a result can be partial.",
            );
        }
        if let Some(name) = chosen {
            self.report = Some(name);
        }
        if run {
            self.run_report(dump, current);
        }
    }

    fn run_report(&mut self, dump: &MemoryDump, report: &Report) {
        let Engine::Ready(tool) = &self.engine else {
            return;
        };
        match tool.start(dump, &report.plugin()) {
            Ok(job) => {
                let id = job.run.id.clone();
                self.jobs.push(job);
                self.reload_runs();
                self.selected_run = Some(id);
                self.result = None;
                self.status = None;
            }
            Err(error) => self.status = Some((error, true)),
        }
    }
}
