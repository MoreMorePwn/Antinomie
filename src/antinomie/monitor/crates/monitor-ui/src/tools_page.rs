// SPDX-License-Identifier: GPL-3.0-only
//! Library > Analysis tools: the optional static-analysis tools, whether the
//! system has them, and installing Antinomie's own copy when it does not.
use crate::theme;
use crate::widgets::{chip, Tone};
use antinomie_monitor_core::geoip::{self, Origin, Status};
use antinomie_monitor_core::{
    analysis_tools::{self, ToolInstall, ToolStatus},
    Command,
};
use eframe::egui::{self, RichText};

/// A program a network route can use, run as a separate process of the
/// analyst's: whether it was found on `PATH` the last time this was looked
/// up (at startup and when Tools > Settings > Network routes opens).
#[derive(Clone, Debug)]
pub(crate) struct RouteProgram {
    pub name: &'static str,
    pub purpose: &'static str,
    pub licence: &'static str,
    pub path: Option<std::path::PathBuf>,
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
    egui::ScrollArea::vertical()
        .id_salt("analysis_tools")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label("Tools used by static analysis.").on_hover_text(
                "Static analysis uses these tools when they are installed on this system. \
                 When one is missing, Antinomie can download it from its upstream release \
                 (checked by SHA-256) into its data folder; the analysis sandbox uses it \
                 read-only.",
            );
            ui.add_space(6.0);
            theme::section(ui, "Tools");
            for tool in tools
                .iter()
                .filter(|tool| !analysis_tools::is_route_tool(&tool.id))
            {
                ui.separator();
                if let Some(next) = tool_row(ui, tool, install, enabled) {
                    command = Some(next);
                }
            }
            ui.add_space(8.0);
            theme::section(ui, "Network route programs");
            ui.add(
                egui::Label::new(
                    "Network routes run these programs as separate processes. Tor and wireproxy \
                     are installed from Tools > Settings > Network routes when the system has none; \
                     INetSim you install from your distribution.",
                )
                .wrap(),
            );
            for program in route_programs
                .iter()
                .filter(|program| !analysis_tools::is_route_tool(program.name))
            {
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
                            ui.colored_label(theme::neutral_accent(), "Not found on PATH");
                        }
                    }
                    ui.weak(program.licence);
                });
            }
            ui.separator();
            egui::CollapsingHeader::new("Licenses")
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "capa Apache-2.0; Detect It Easy MIT (with Qt LGPL-3.0 and ICU); \
                             Ghidra Apache-2.0 with the Eclipse Temurin JDK (GPL-2.0 with Classpath \
                             exception); pySigma LGPL-3.0 with its SQLite backend LGPL-2.1, installed \
                             from PyPI into its own environment; Magika Apache-2.0 (Google), one \
                             executable from its GitHub release, which the Properties panel prefers \
                             over a system copy.",
                        )
                        .small()
                        .weak(),
                    );
                });
        });
    command
}

fn origin_text(origin: Origin) -> &'static str {
    match origin {
        Origin::System => "TShark's own folder",
        Origin::Managed => "Antinomie's DB-IP Lite copy",
        Origin::Folder => "your folder",
    }
}

/// The databases TShark has, as chips and paths, and the Warning when
/// Country or Organization would stay empty.
pub(crate) fn geoip_status(ui: &mut egui::Ui, status: Option<&Status>) {
    let Some(status) = status else {
        theme::loading_weak(ui, "Looking for databases…");
        return;
    };
    for (label, found, location) in [
        ("Country / city", status.has_location(), true),
        ("Organization (AS)", status.has_asn(), false),
    ] {
        let details: Vec<String> = status
            .databases
            .iter()
            .filter(|database| {
                matches!(database.kind, geoip::Kind::Country | geoip::Kind::City) == location
            })
            .map(|database| {
                format!(
                    "{} · {} · {}",
                    database.name,
                    origin_text(database.origin),
                    database.path.display()
                )
            })
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(label).strong().color(theme::heading()));
            let response = if found {
                chip(ui, "Database found".to_owned(), Tone::Good)
            } else {
                chip(ui, "No database".to_owned(), Tone::Accent)
            };
            if !details.is_empty() {
                response.on_hover_text(details.join("\n"));
            }
        });
    }
    if let Some(warning) = status.warning() {
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(warning).color(theme::warn())).wrap());
    }
}

/// The attribution DB-IP's licence asks for, with its link.
pub(crate) fn geoip_attribution(ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.hyperlink_to(geoip::ATTRIBUTION, geoip::ATTRIBUTION_URL);
        ui.weak("· DB-IP Lite databases, ");
        ui.hyperlink_to(geoip::LICENCE, geoip::LICENCE_URL);
    });
}

/// One managed tool: its name, whether the system has it, the version
/// Antinomie installed, and the Install, Remove or Cancel button with the
/// progress of an installation under way. Library > Analysis tools and
/// Tools > Settings > Network routes draw the same row.
pub(crate) fn tool_row(
    ui: &mut egui::Ui,
    tool: &ToolStatus,
    install: Option<&ToolInstall>,
    enabled: bool,
) -> Option<Command> {
    let mut command = None;
    let running = install.is_some_and(|install| !install.finished);
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
                ui.colored_label(theme::good(), format!("Installed by Antinomie ({version})"));
            }
            (None, None) => {
                ui.colored_label(theme::neutral_accent(), "Not installed");
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
                                tool.version.split(' ').next().unwrap_or(&tool.version),
                                crate::values::short_size(tool.size)
                            ))
                            .color(theme::palette().primary_text),
                        )
                        .fill(theme::primary()),
                    )
                    .on_hover_text(format!(
                        "{} · downloads from its upstream release",
                        tool.version
                    ))
                    .clicked()
            {
                command = Some(Command::InstallTool {
                    id: tool.id.clone(),
                });
            }
        });
    });
    // Where Antinomie's own copy is saved, on a line of its own: the path is
    // long and the row's buttons stay at its right.
    if let (None, Some(_), Some(path)) = (&tool.system, &tool.installed, &tool.installed_path) {
        // Relative to the data directory; the full path is on hover.
        let shown = tool.installed_shown.as_deref().unwrap_or(path);
        ui.add(egui::Label::new(RichText::new(shown).monospace().color(theme::muted())).wrap())
            .on_hover_text(path);
    }
    if let Some(install) = install.filter(|install| install.id == tool.id) {
        if install.finished {
            if let Some(error) = &install.error {
                crate::activity::outcome(ui, error);
            }
        } else {
            if !install.note.is_empty() {
                crate::activity::info(ui, install.note.clone());
            }
            let fraction = if install.total > 0 {
                install.received as f32 / install.total as f32
            } else {
                0.0
            };
            ui.add(
                egui::ProgressBar::new(fraction).text(match install.stage.as_str() {
                    "download" => format!(
                        "Downloading {} of {}",
                        crate::values::short_size(install.received),
                        crate::values::short_size(install.total)
                    ),
                    "verify" => "Checking SHA-256".into(),
                    "unpack" => "Unpacking".into(),
                    "prepare" => "Creating the Python environment".into(),
                    "packages" => "Installing the locked Python packages (SHA-256 checked)".into(),
                    stage => stage.to_owned(),
                }),
            );
        }
    }
    command
}
