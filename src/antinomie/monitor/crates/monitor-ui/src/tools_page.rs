//! Library > Analysis tools: the optional static-analysis tools, whether the
//! system has them, and installing Antinomie's own copy when it does not.
use crate::theme;
use antinomie_monitor_core::{
    analysis_tools::{ToolInstall, ToolStatus},
    Command,
};
use eframe::egui::{self, RichText};

/// A program a network route can use, run as a separate process of the
/// analyst's: whether it was found on `PATH` the last time this was looked
/// up (at startup and when Settings > Network routes opens).
#[derive(Clone, Debug)]
pub(crate) struct RouteProgram {
    pub name: &'static str,
    pub purpose: &'static str,
    pub licence: &'static str,
    pub path: Option<std::path::PathBuf>,
}

fn size(bytes: u64) -> String {
    crate::values::file_size(bytes)
}

/// Draw the page; returns a command to send.
pub(crate) fn show(
    ui: &mut egui::Ui,
    tools: &[ToolStatus],
    install: Option<&ToolInstall>,
    enabled: bool,
    route_programs: &[RouteProgram],
) -> Option<Command> {
    let mut command = None;
    let running = install.is_some_and(|install| !install.finished);
    egui::ScrollArea::vertical()
        .id_salt("analysis_tools")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label(
                "Static analysis uses these tools when they are installed on this system. \
                 When one is missing, Antinomie can download it from its upstream release \
                 (checked by SHA-256) into its data folder; the analysis sandbox uses it \
                 read-only.",
            );
            ui.add_space(6.0);
            theme::section(ui, "Tools");
            for tool in tools {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&tool.name).strong().color(theme::heading()));
                    ui.label(RichText::new(&tool.purpose).color(theme::muted()));
                });
                ui.horizontal_wrapped(|ui| {
                    match (&tool.system, &tool.installed) {
                        (Some(path), installed) => {
                            ui.colored_label(theme::good(), "On this system");
                            ui.label(RichText::new(path).monospace().color(theme::muted()));
                            if let Some(version) = installed {
                                ui.weak(if tool.id == "magika" {
                                    // The Properties panel looks here first.
                                    format!("(Antinomie's {version} also installed; used first)")
                                } else {
                                    format!("(Antinomie's {version} also installed; unused)")
                                });
                            }
                        }
                        (None, Some(version)) => {
                            ui.colored_label(
                                theme::good(),
                                format!("Installed by Antinomie ({version})"),
                            );
                        }
                        (None, None) => {
                            ui.colored_label(theme::warn(), "Not installed");
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let this = install.filter(|install| install.id == tool.id);
                        if this.is_some_and(|install| !install.finished) {
                            if ui.button("Cancel").clicked() {
                                command = Some(Command::CancelToolInstall);
                            }
                        } else if tool.installed.is_some() {
                            if ui
                                .add_enabled(enabled && !running, egui::Button::new("Remove"))
                                .on_hover_text("Delete Antinomie's copy")
                                .clicked()
                            {
                                command = Some(Command::RemoveTool {
                                    id: tool.id.clone(),
                                });
                            }
                        } else if tool.system.is_none()
                            && ui
                                .add_enabled(
                                    enabled && !running,
                                    egui::Button::new(
                                        RichText::new(format!(
                                            "Install {} · {}",
                                            tool.version,
                                            size(tool.size)
                                        ))
                                        .color(theme::palette().primary_text),
                                    )
                                    .fill(theme::primary()),
                                )
                                .clicked()
                        {
                            command = Some(Command::InstallTool {
                                id: tool.id.clone(),
                            });
                        }
                    });
                });
                if let Some(install) = install.filter(|install| install.id == tool.id) {
                    if install.finished {
                        if let Some(error) = &install.error {
                            crate::activity::error_toast(ui, error);
                        }
                    } else {
                        let fraction = if install.total > 0 {
                            install.received as f32 / install.total as f32
                        } else {
                            0.0
                        };
                        ui.add(egui::ProgressBar::new(fraction).text(
                            match install.stage.as_str() {
                                "download" => format!(
                                    "Downloading {} of {}",
                                    size(install.received),
                                    size(install.total)
                                ),
                                "verify" => "Checking SHA-256".into(),
                                "unpack" => "Unpacking".into(),
                                "prepare" => "Creating the Python environment".into(),
                                "packages" => {
                                    "Installing the locked Python packages (SHA-256 checked)".into()
                                }
                                stage => stage.to_owned(),
                            },
                        ));
                    }
                }
            }
            ui.add_space(8.0);
            theme::section(ui, "Network route programs");
            ui.add(
                egui::Label::new(
                    "Network routes use these programs, which you install from your \
                     distribution; Antinomie runs them as separate processes and does not \
                     bundle them. The routes are set up in Settings > Network routes.",
                )
                .wrap(),
            );
            for program in route_programs {
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(program.name).strong().color(theme::heading()));
                    ui.label(RichText::new(program.purpose).color(theme::muted()));
                    match &program.path {
                        Some(path) => {
                            ui.colored_label(theme::good(), "On this system");
                            ui.label(
                                RichText::new(path.display().to_string())
                                    .monospace()
                                    .color(theme::muted()),
                            );
                        }
                        None => {
                            ui.colored_label(theme::warn(), "Not found on PATH");
                        }
                    }
                    ui.weak(program.licence);
                });
            }
            ui.separator();
            ui.label(
                RichText::new(
                    "Licenses: capa Apache-2.0; Detect It Easy MIT (with Qt LGPL-3.0 and ICU); \
                     Ghidra Apache-2.0 with the Eclipse Temurin JDK (GPL-2.0 with Classpath \
                     exception); pySigma LGPL-3.0 with its SQLite backend LGPL-2.1, installed \
                     from PyPI into its own environment; Magika Apache-2.0 (Google), one \
                     executable from its GitHub release, which the Properties panel prefers \
                     over a system copy. Set ANTINOMIE_ANALYSIS_TOOLS=managed to prefer \
                     Antinomie's copies over the system's elsewhere.",
                )
                .small()
                .weak(),
            );
        });
    command
}
