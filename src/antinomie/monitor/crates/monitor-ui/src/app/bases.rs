// SPDX-License-Identifier: MIT
//! Base image choice and the download window.
use super::*;

impl MonitorApp {
    pub(super) fn open_downloads(&mut self) {
        self.download_open = true;
        if !self.snapshot.remote_refreshing {
            self.send(Command::RefreshRemoteBases);
        }
    }

    /// Add base > Download base: bases for this version first, older ones
    /// behind a toggle; one row per base with its action on the right and
    /// persistent progress and Cancel above the scrollable catalog.
    pub(super) fn download_window(
        &mut self,
        ctx: &egui::Context,
        open: &mut bool,
    ) -> Option<Command> {
        let mut command = None;
        let installed: Vec<String> = self.snapshot.bases.iter().map(|b| b.id.clone()).collect();
        let download = self.snapshot.download.clone();
        let busy = download.as_ref().is_some_and(|status| !status.finished);
        let (current, rest): (Vec<_>, Vec<_>) = self
            .snapshot
            .remote_bases
            .iter()
            .cloned()
            .partition(remote_is_current);
        let (older, other): (Vec<_>, Vec<_>) = rest.into_iter().partition(|base| {
            matches!(
                RevisionStatus::of_base(base.revision, base.min_app_version.as_deref()),
                RevisionStatus::Outdated | RevisionStatus::Legacy
            )
        });
        let show_older = &mut self.show_older_bases;
        crate::widgets::window("Download base")
            .id(Dialog::Download.window_id())
            .open(open)
            .collapsible(false)
            .resizable(true)
            .default_size([760.0, 520.0])
            .min_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.snapshot.remote_refreshing,
                            egui::Button::new("Refresh catalog"),
                        )
                        .clicked()
                    {
                        command = Some(Command::RefreshRemoteBases);
                    }
                    if self.snapshot.remote_refreshing {
                        crate::theme::loading(ui, "Fetching catalog…");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_enabled(
                            !older.is_empty(),
                            egui::Checkbox::new(
                                show_older,
                                format!("Show older bases ({})", older.len()),
                            ),
                        )
                        .on_hover_text("Bases built for earlier Antinomie versions");
                    });
                });
                if let Some(error) = &self.snapshot.remote_error {
                    crate::activity::error(ui, error);
                }
                if let Some(next) = download_status(ui, download.as_ref()) {
                    command = Some(next);
                }
                ui.separator();
                if current.is_empty() && older.is_empty() && other.is_empty() {
                    ui.colored_label(theme::muted(), "No bases listed yet: refresh the catalog.");
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let rows = current
                            .iter()
                            .chain(other.iter())
                            .chain(older.iter().filter(|_| *show_older));
                        if !current.is_empty() {
                            theme::section(ui, &format!("For Antinomie {APP_VERSION}"));
                        }
                        for (index, base) in rows.enumerate() {
                            if index == current.len() && !other.is_empty() {
                                ui.add_space(6.0);
                                theme::section(ui, "Other bases");
                            }
                            if index == current.len() + other.len() && *show_older {
                                ui.add_space(6.0);
                                theme::section(ui, "Older bases");
                            }
                            egui::Frame::group(ui.style())
                                .inner_margin(egui::Margin::symmetric(10, 8))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    if let Some(next) =
                                        download_row(ui, base, &installed, download.as_ref(), busy)
                                    {
                                        command = Some(next);
                                    }
                                });
                        }
                    });
            });
        command
    }
}

/// The running download's Cancel, label and progress bar, or how the last
/// one ended. Shared by the Download base window and Getting started.
pub(super) fn download_status(
    ui: &mut egui::Ui,
    download: Option<&antinomie_monitor_core::DownloadStatus>,
) -> Option<Command> {
    let mut command = None;
    if let Some(status) = download.filter(|status| !status.finished) {
        ui.separator();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!status.installing, egui::Button::new("Cancel"))
                .on_disabled_hover_text("Finishing the base installation")
                .clicked()
            {
                command = Some(Command::CancelDownload);
            }
            ui.label(if status.installing {
                format!("{}: installing…", status.label)
            } else {
                status.label.clone()
            });
        });
        let fraction = if status.total > 0 {
            (status.received as f32 / status.total as f32).clamp(0.0, 1.0)
        } else {
            0.0
        };
        ui.add(egui::ProgressBar::new(fraction).text(format!(
            "{} of {}",
            human_bytes(status.received),
            human_bytes(status.total)
        )));
    }
    if let Some(status) = download.filter(|status| status.finished) {
        match &status.error {
            Some(error) if error.contains("cancelled") => {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "{}: download cancelled; it resumes where it stopped",
                        status.label
                    ),
                );
            }
            Some(error) => {
                crate::activity::error(ui, format!("{}: {error}", status.label));
            }
            None => {
                ui.colored_label(theme::good(), format!("{} installed", status.label));
            }
        }
    }
    command
}

pub(super) fn base_selector(
    ui: &mut egui::Ui,
    snapshot: &Snapshot,
    identity: &mut Option<String>,
    salt: &str,
) {
    let label = if identity.is_none() {
        match selected_base(snapshot, None) {
            Some(base) if !base.fixed_display => "Application default (legacy)".into(),
            _ => "Application default".into(),
        }
    } else {
        selected_base(snapshot, identity.as_deref())
            .map(base_choice_label)
            .unwrap_or_else(|| "Linux 6.12.94 (unavailable)".into())
    };
    // A fixed width, the name cut to fit (whole on hover): a long base name
    // would otherwise push into the column beside the form. egui cuts the
    // text at the width available, so the box gets exactly the Name field's.
    let width = 296.0;
    ui.allocate_ui_with_layout(
        egui::vec2(width, ui.spacing().interact_size.y),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_max_width(width);
            egui::ComboBox::from_id_salt(salt)
                .selected_text(label.clone())
                .width(width)
                .truncate()
                .show_ui(ui, |ui| {
                    for base in &snapshot.bases {
                        ui.selectable_value(
                            identity,
                            Some(base.id.clone()),
                            base_choice_label(base),
                        )
                        .on_hover_text(base.directory.display().to_string());
                    }
                })
                .response
                .on_hover_text(label);
        },
    );
}

/// One catalog base: name and facts on the left; installed, Download, or
/// the running download's state on the right. Cancel stays above the list.
pub(super) fn download_row(
    ui: &mut egui::Ui,
    base: &antinomie_monitor_core::RemoteBase,
    installed: &[String],
    download: Option<&antinomie_monitor_core::DownloadStatus>,
    busy: bool,
) -> Option<Command> {
    let mut command = None;
    let status = RevisionStatus::of_base(base.revision, base.min_app_version.as_deref());
    let running = download.filter(|d| d.identity == base.identity && !d.finished);
    ui.horizontal(|ui| {
        let action_width = 150.0;
        ui.allocate_ui_with_layout(
            egui::vec2((ui.available_width() - action_width).max(200.0), 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.label(
                    RichText::new(versioned_label(
                        &base.label,
                        base.revision,
                        base.min_app_version.as_deref(),
                    ))
                    .strong(),
                );
                let short = &base.identity[..12.min(base.identity.len())];
                let mut facts = vec![
                    format!("Linux {}", base.kernel_version),
                    human_bytes(base.total_size),
                    format!(
                        "{} MiB RAM, {} GiB disk minimum",
                        base.min_ram_mib, base.min_disk_gib
                    ),
                    short.to_string(),
                ];
                if status == RevisionStatus::Outdated {
                    facts.insert(0, "Outdated".into());
                }
                ui.label(
                    RichText::new(facts.join("  ·  "))
                        .small()
                        .color(theme::muted()),
                );
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if installed.contains(&base.identity) {
                ui.colored_label(
                    theme::good(),
                    format!("{} Installed", egui_phosphor::regular::CHECK),
                );
            } else if running.is_some() {
                // Right to left: the label first puts the spinner on its left.
                ui.label(if running.is_some_and(|status| status.installing) {
                    "Installing…"
                } else {
                    "Downloading…"
                });
                crate::theme::spinner(ui);
            } else if status == RevisionStatus::NeedsNewerApp {
                ui.add_enabled(false, egui::Button::new("Download"))
                    .on_disabled_hover_text(format!(
                        "Built for a newer Antinomie (this is Antinomie {APP_VERSION})"
                    ));
            } else if ui
                .add_enabled(
                    !busy,
                    primary_button(&format!(
                        "{} Download",
                        egui_phosphor::regular::DOWNLOAD_SIMPLE
                    )),
                )
                .on_disabled_hover_text("Another download is in progress")
                .clicked()
            {
                command = Some(Command::DownloadBase {
                    identity: base.identity.clone(),
                });
            }
        });
    });
    command
}

/// A base's name with the Antinomie version it is for, e.g.
/// "Debian 13 (GNOME) · Antinomie 0.2.0".
pub(super) fn versioned_label(
    label: &str,
    revision: Option<u32>,
    min_app_version: Option<&str>,
) -> String {
    match antinomie_monitor_core::base_app_version(revision, min_app_version) {
        Some(version) => format!("{label} · Antinomie {version}"),
        None => label.to_string(),
    }
}

/// Whether a remote base is for this app version (not an older one, and
/// not one this app is too old for).
pub(super) fn remote_is_current(base: &antinomie_monitor_core::RemoteBase) -> bool {
    RevisionStatus::of_base(base.revision, base.min_app_version.as_deref())
        == RevisionStatus::Current
}

/// The catalog base that replaces an outdated installed one: same name,
/// built for this app version.
pub(super) fn newer_base<'a>(
    snapshot: &'a Snapshot,
    base: &BaseSummary,
) -> Option<&'a antinomie_monitor_core::RemoteBase> {
    snapshot
        .remote_bases
        .iter()
        .find(|remote| remote.label == base.label && remote_is_current(remote))
}

pub(super) fn base_choice_label(base: &BaseSummary) -> String {
    let name = versioned_label(&base.label, base.revision, base.min_app_version.as_deref());
    let label = if base.fixed_display {
        name
    } else {
        format!("{name} (legacy)")
    };
    if RevisionStatus::of_base(base.revision, base.min_app_version.as_deref())
        == RevisionStatus::Current
    {
        label
    } else {
        format!("{label} · {}", describe_base(base))
    }
}

/// "for Antinomie 0.1.0" etc., plus the version that built the base.
pub(super) fn describe_base(base: &BaseSummary) -> String {
    let status = RevisionStatus::describe(base.revision, base.min_app_version.as_deref());
    match &base.built_with {
        Some(version) => format!("{status} (built with {version})"),
        None => status,
    }
}

/// Resolve the explicit base or the same legacy default used by VM configuration.
pub(crate) fn selected_base<'a>(
    snapshot: &'a Snapshot,
    identity: Option<&str>,
) -> Option<&'a BaseSummary> {
    if let Some(identity) = identity {
        return snapshot.bases.iter().find(|base| base.id == identity);
    }
    snapshot
        .bases
        .iter()
        .find(|base| base.guest.is_none())
        .or_else(|| snapshot.bases.first())
}

pub(super) fn preferred_new_base<'a>(
    snapshot: &'a Snapshot,
    directory: &str,
) -> Option<&'a BaseSummary> {
    let configured = snapshot
        .bases
        .iter()
        .find(|base| base.directory == std::path::Path::new(directory))
        .or_else(|| selected_base(snapshot, None));
    if let Some(configured) = configured {
        return Some(configured)
            .filter(|base| base.fixed_display)
            .or_else(|| {
                snapshot.bases.iter().find(|base| {
                    base.fixed_display
                        && base.guest.as_ref().map(|guest| &guest.id)
                            == configured.guest.as_ref().map(|guest| &guest.id)
                })
            })
            .or(Some(configured));
    }
    snapshot
        .bases
        .iter()
        .find(|base| base.fixed_display)
        .or_else(|| snapshot.bases.first())
}
