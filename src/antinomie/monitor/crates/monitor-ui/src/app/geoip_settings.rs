// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Network lookup: the MaxMind-format databases TShark reads for the
//! country and organization of public addresses. It says what TShark has,
//! warns when it has nothing, installs the DB-IP Lite copy (the managed
//! `geoip` tool, so Cancel and resume work as for every download), takes a
//! newer month on request, and accepts a folder of GeoLite2 files.
use super::widgets::{icon, text_field};
use super::*;
use crate::{
    tools_page,
    widgets::{chip, Tone},
};
use antinomie_monitor_core::{
    analysis_tools::{ToolInstall, ToolStatus},
    geoip::{self, Latest, Origin, Status},
};
use eframe::egui::RichText;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::AtomicBool,
    mpsc::{self, Receiver},
    Arc,
};

type Checked = Result<Latest, String>;

enum Message {
    Progress(String, u64, u64),
    Done(Result<(), String>),
}

/// A newer month being taken (see `geoip::update_latest`).
struct Update {
    messages: Receiver<Message>,
    cancel: Arc<AtomicBool>,
    stage: String,
    received: u64,
    total: u64,
    note: String,
}

#[derive(Default)]
pub(crate) struct GeoipState {
    /// What TShark can use, from the last look.
    status: Option<Status>,
    looking: Option<Receiver<Status>>,
    /// What the last look was made for: the installed month and the folder.
    seen: Option<(Option<String>, Option<PathBuf>)>,
    /// Bumped when a newer month was taken, so the next frame looks again.
    generation: u32,
    seen_generation: u32,
    latest: Option<Checked>,
    checking: Option<Receiver<Checked>>,
    update: Option<Update>,
    update_error: Option<String>,
    asked_once: bool,
}

impl GeoipState {
    /// What TShark can use, once the first look has finished.
    pub(crate) fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Every frame: collect finished work and look again when the installed
    /// databases or the chosen folder changed. The path list TShark is started
    /// with is written here, so the first scan already uses it.
    pub(crate) fn sync(
        &mut self,
        ctx: &egui::Context,
        data_dir: &Path,
        folder: Option<&Path>,
        installed: Option<String>,
    ) {
        if let Some(receiver) = &self.looking {
            match receiver.try_recv() {
                Ok(status) => {
                    self.status = Some(status);
                    self.looking = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.looking = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(receiver) = &self.checking {
            match receiver.try_recv() {
                Ok(answer) => {
                    self.latest = Some(answer);
                    self.checking = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.checking = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.poll_update();
        let key = (installed, folder.map(Path::to_path_buf));
        if self.looking.is_some()
            || (self.seen.as_ref() == Some(&key) && self.seen_generation == self.generation)
        {
            return;
        }
        geoip::configure(data_dir, folder);
        self.seen = Some(key);
        self.seen_generation = self.generation;
        let (sender, receiver) = mpsc::sync_channel(1);
        let (data_dir, folder, wake) = (
            data_dir.to_path_buf(),
            folder.map(Path::to_path_buf),
            ctx.clone(),
        );
        if std::thread::Builder::new()
            .name("antinomie-geoip-detect".into())
            .spawn(move || {
                let _ = sender.send(geoip::detect(&data_dir, folder.as_deref()));
                wake.request_repaint();
            })
            .is_ok()
        {
            self.looking = Some(receiver);
        }
    }

    fn poll_update(&mut self) {
        let Some(update) = &mut self.update else {
            return;
        };
        let mut finished = None;
        while let Ok(message) = update.messages.try_recv() {
            match message {
                Message::Progress(stage, received, total) => {
                    if let Some(note) = stage.strip_prefix("note:") {
                        update.note = note.to_owned();
                    } else {
                        update.stage = stage;
                        update.received = received;
                        update.total = total;
                    }
                }
                Message::Done(result) => finished = Some(result),
            }
        }
        if let Some(result) = finished {
            self.update = None;
            match result {
                Ok(()) => {
                    self.update_error = None;
                    self.latest = None;
                    self.generation += 1;
                }
                Err(error) => self.update_error = Some(error),
            }
        }
    }

    fn start_check(&mut self, ctx: &egui::Context, curl: &Path) {
        if self.checking.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let (curl, wake) = (curl.to_path_buf(), ctx.clone());
        if std::thread::Builder::new()
            .name("antinomie-geoip-check".into())
            .spawn(move || {
                let _ = sender.send(geoip::check_latest(&curl));
                wake.request_repaint();
            })
            .is_ok()
        {
            self.checking = Some(receiver);
        }
    }

    fn start_update(&mut self, ctx: &egui::Context, curl: &Path, data_dir: &Path, month: String) {
        if self.update.is_some() {
            return;
        }
        let (sender, messages) = mpsc::channel();
        let cancel = antinomie_monitor_core::cancel::flag();
        let (curl, data_dir, flag, wake) = (
            curl.to_path_buf(),
            data_dir.to_path_buf(),
            cancel.clone(),
            ctx.clone(),
        );
        let progress = sender.clone();
        let spawned = std::thread::Builder::new()
            .name("antinomie-geoip-update".into())
            .spawn(move || {
                let result = geoip::update_latest(
                    &curl,
                    &data_dir,
                    &month,
                    &flag,
                    |stage, received, total| {
                        let _ = progress.send(Message::Progress(stage.to_owned(), received, total));
                        wake.request_repaint();
                    },
                );
                let _ = sender.send(Message::Done(result));
                wake.request_repaint();
            });
        if spawned.is_ok() {
            self.update_error = None;
            self.update = Some(Update {
                messages,
                cancel,
                stage: "download".into(),
                received: 0,
                total: 0,
                note: String::new(),
            });
        }
    }
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
pub(crate) fn status_lines(ui: &mut egui::Ui, status: Option<&Status>) {
    let Some(status) = status else {
        crate::theme::loading_weak(ui, "Looking for databases…");
        return;
    };
    for (label, found) in [
        ("Country / city", status.has_location()),
        ("Organization (AS)", status.has_asn()),
    ] {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(label).strong().color(theme::heading()));
            if found {
                chip(ui, "Database found".to_owned(), Tone::Good);
            } else {
                chip(ui, "No database".to_owned(), Tone::Accent);
            }
        });
    }
    for database in &status.databases {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} · {} · {}",
                    database.name,
                    origin_text(database.origin),
                    database.path.display()
                ))
                .small()
                .monospace()
                .color(theme::muted()),
            )
            .wrap(),
        );
    }
    if let Some(warning) = status.warning() {
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(warning).color(theme::warn())).wrap());
    }
}

/// The attribution DB-IP's licence asks for, with its link.
pub(crate) fn attribution(ui: &mut egui::Ui) {
    ui.horizontal_wrapped(|ui| {
        ui.hyperlink_to(geoip::ATTRIBUTION, geoip::ATTRIBUTION_URL);
        ui.weak("· DB-IP Lite databases, ");
        ui.hyperlink_to(geoip::LICENCE, geoip::LICENCE_URL);
    });
}

impl MonitorApp {
    /// Every frame (see [`GeoipState::sync`]).
    pub(super) fn geoip_sync(&mut self, ctx: &egui::Context) {
        let installed = self
            .snapshot
            .analysis_tools
            .iter()
            .find(|tool| tool.id == geoip::TOOL_ID)
            .and_then(|tool| tool.installed.clone());
        self.geoip.sync(
            ctx,
            &self.options.data_dir,
            self.settings.geoip_folder.as_deref(),
            installed,
        );
    }

    /// The Network lookup page's database section.
    pub(super) fn geoip_section(&mut self, ui: &mut egui::Ui) {
        theme::section(ui, "IP geolocation database (TShark)");
        ui.add(
            egui::Label::new(
                "TShark fills Country and Organization only from MaxMind-format (.mmdb) \
                 databases; the old GeoIP.dat files are ignored. Antinomie hands its own \
                 copy to its TShark runs only and never changes your Wireshark settings.",
            )
            .wrap(),
        );
        ui.add_space(4.0);
        status_lines(ui, self.geoip.status());
        ui.add_space(6.0);
        let tool = self
            .snapshot
            .analysis_tools
            .iter()
            .find(|tool| tool.id == geoip::TOOL_ID)
            .cloned();
        let managed = self
            .geoip
            .status()
            .and_then(|status| status.managed.clone());
        let enabled = !self.closing;
        let mut command = None;
        if let (Some(managed), Some(tool)) = (&managed, &tool) {
            command = self.managed_row(ui, managed, tool);
        } else if let Some(tool) = &tool {
            ui.label(
                RichText::new("DB-IP Lite (free, no account)")
                    .strong()
                    .color(theme::heading()),
            );
            let install: Option<ToolInstall> = self.snapshot.tool_install.clone();
            command = tools_page::tool_row(ui, tool, install.as_ref(), enabled);
            hint_line(
                ui,
                "Country and AS databases from db-ip.com, CC BY 4.0. By installing you accept \
                 that licence and the attribution it asks for. A cancelled download is kept \
                 and resumed when you install again.",
            );
        }
        if let Some(command) = command {
            self.send(command);
        }
        ui.add_space(6.0);
        self.refresh_row(ui, managed.as_ref());
        ui.add_space(6.0);
        self.folder_row(ui);
        ui.add_space(6.0);
        attribution(ui);
    }

    fn managed_row(
        &mut self,
        ui: &mut egui::Ui,
        managed: &geoip::Managed,
        tool: &ToolStatus,
    ) -> Option<Command> {
        let mut command = None;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("DB-IP Lite").strong().color(theme::heading()));
            ui.colored_label(
                theme::good(),
                format!("Installed by Antinomie ({})", managed.month),
            );
            if !managed.pinned {
                ui.weak("newer month; its SHA-256 was recorded, not checked against a pin");
            }
            let busy = self
                .snapshot
                .tool_install
                .as_ref()
                .is_some_and(|i| !i.finished);
            if ui
                .add_enabled(
                    !busy && self.geoip.update.is_none(),
                    egui::Button::new("Remove"),
                )
                .on_hover_text("Delete Antinomie's copy")
                .clicked()
            {
                command = Some(Command::RemoveTool {
                    id: tool.id.clone(),
                });
            }
        });
        command
    }

    fn refresh_row(&mut self, ui: &mut egui::Ui, managed: Option<&geoip::Managed>) {
        let outbound = self.settings.outbound_catalog;
        let curl = self.options.curl.clone();
        let ctx = ui.ctx().clone();
        // Once per session, when downloads are allowed and a copy exists.
        if outbound && managed.is_some() && !self.geoip.asked_once {
            self.geoip.asked_once = true;
            self.geoip.start_check(&ctx, &curl);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Monthly refresh")
                    .strong()
                    .color(theme::heading()),
            );
            let idle = self.geoip.checking.is_none() && self.geoip.update.is_none();
            if ui
                .add_enabled(
                    outbound && idle,
                    egui::Button::new("Check for a newer month"),
                )
                .on_hover_text("Two small requests to download.db-ip.com; nothing is downloaded")
                .on_disabled_hover_text(
                    "Turn on Settings > Detection > Allow outbound catalog and rule downloads",
                )
                .clicked()
            {
                self.geoip.start_check(&ctx, &curl);
            }
            if self.geoip.checking.is_some() {
                ui.spinner();
            }
        });
        if !outbound {
            hint_line(
                ui,
                "Checking for a newer month needs Settings > Detection > Allow outbound catalog and rule downloads.",
            );
        }
        match self.geoip.latest.clone() {
            Some(Ok(latest)) => {
                let installed = managed.map(|m| m.month.as_str());
                if installed.is_some_and(|month| month >= latest.month.as_str()) {
                    ui.weak(format!("Up to date: {} is the newest month.", latest.month));
                } else if self.geoip.update.is_none() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("DB-IP published {}.", latest.month));
                        if ui
                            .button(format!("Download {}", latest.month))
                            .on_hover_text(
                                "DB-IP publishes no signature, so a newer month cannot be checked \
                                 against a pinned SHA-256: it is fetched over HTTPS and its hash is \
                                 recorded in the tool record. The month pinned in Antinomie stays \
                                 checked.",
                            )
                            .clicked()
                        {
                            let data_dir = self.options.data_dir.clone();
                            self.geoip.start_update(&ctx, &curl, &data_dir, latest.month);
                        }
                    });
                }
            }
            Some(Err(error)) => {
                ui.colored_label(theme::warn(), format!("Could not ask DB-IP: {error}"));
            }
            None => {}
        }
        if let Some(update) = &self.geoip.update {
            if !update.note.is_empty() {
                crate::activity::info(ui, update.note.clone());
            }
            let fraction = if update.total > 0 {
                update.received as f32 / update.total as f32
            } else {
                0.0
            };
            let text = match update.stage.as_str() {
                "download" => format!(
                    "Downloading {} of about {}",
                    antinomie_monitor_core::byte_size::short_size(update.received),
                    antinomie_monitor_core::byte_size::short_size(update.total)
                ),
                "verify" => "Recording SHA-256".to_owned(),
                "unpack" => "Unpacking".to_owned(),
                other => other.to_owned(),
            };
            ui.add(egui::ProgressBar::new(fraction).text(text));
            if ui.button("Cancel").clicked() {
                update
                    .cancel
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if let Some(error) = &self.geoip.update_error {
            crate::activity::outcome(ui, error);
        }
    }

    fn folder_row(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new("Your own GeoLite2 folder")
                .strong()
                .color(theme::heading()),
        );
        let mut text = self
            .settings
            .geoip_folder
            .as_deref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            let width = (ui.available_width()
                - ui.spacing().interact_size.y * 2.0
                - ui.spacing().item_spacing.x * 2.0
                - theme::TEXT_EDIT_MARGIN.sum().x)
                .clamp(24.0, 480.0);
            if ui
                .add(
                    text_field(&mut text)
                        .desired_width(width)
                        .font(egui::TextStyle::Monospace)
                        .hint_text(theme::hint_text(
                            "Folder with GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb",
                        )),
                )
                .changed()
            {
                self.settings.geoip_folder =
                    (!text.trim().is_empty()).then(|| crate::folders::user_path(&text));
            }
            if icon(
                ui,
                egui_phosphor::regular::FOLDER_OPEN,
                "Choose the folder",
                self.folder_picker.available(),
            ) {
                if let Err(error) = self.folder_picker.choose(FolderTarget {
                    generation: 0,
                    kind: FolderKind::GeoipFolder,
                }) {
                    self.report_error(error);
                }
            }
            if icon(
                ui,
                egui_phosphor::regular::X,
                "Stop using this folder",
                self.settings.geoip_folder.is_some(),
            ) {
                self.settings.geoip_folder = None;
            }
        });
        hint_line(
            ui,
            "A folder of MaxMind GeoLite2 or GeoIP2 .mmdb files (Country or City, and ASN), \
             read in place. Needs a MaxMind account to download; Antinomie does not.",
        );
    }
}

fn hint_line(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap());
}
