// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Network lookup: the MaxMind-format databases TShark reads for the
//! country and organization of public addresses. It says what TShark has,
//! warns when it has nothing, installs the DB-IP Lite copy (the managed
//! `geoip` tool, so Cancel and resume work as for every download), takes a
//! newer month on request, and accepts a folder of GeoLite2 files.
use super::super::widgets::{icon, text_field};
use super::super::*;
use crate::tools_page;
use antinomie_monitor_core::{
    analysis_tools::{ToolInstall, ToolStatus},
    geoip::{self, Latest, Status},
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
    /// Settings > Network lookup: a folder of MaxMind-format databases,
    /// saved in the data folder (`geoip/folder`) like the route settings.
    pub(super) folder: Option<PathBuf>,
    folder_loaded: bool,
}

impl GeoipState {
    /// What TShark can use, once the first look has finished.
    pub(crate) fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Choose or clear the folder, and save the choice.
    pub(crate) fn set_folder(&mut self, data_dir: &Path, folder: Option<PathBuf>) {
        let file = data_dir.join("geoip").join("folder");
        match &folder {
            Some(path) => {
                let _ = std::fs::create_dir_all(data_dir.join("geoip"));
                let _ = std::fs::write(&file, path.to_string_lossy().as_bytes());
            }
            None => {
                let _ = std::fs::remove_file(&file);
            }
        }
        self.folder = folder;
        self.folder_loaded = true;
    }

    /// Every frame: collect finished work and look again when the installed
    /// databases or the chosen folder changed. The path list TShark is started
    /// with is written here, so the first scan already uses it.
    pub(crate) fn sync(&mut self, ctx: &egui::Context, data_dir: &Path, installed: Option<String>) {
        if !self.folder_loaded {
            self.folder_loaded = true;
            self.folder = std::fs::read_to_string(data_dir.join("geoip").join("folder"))
                .ok()
                .map(|text| PathBuf::from(text.trim()))
                .filter(|path| !path.as_os_str().is_empty());
        }
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
        let folder = self.folder.clone();
        let key = (installed, folder.clone());
        if self.looking.is_some()
            || (self.seen.as_ref() == Some(&key) && self.seen_generation == self.generation)
        {
            return;
        }
        geoip::configure(data_dir, folder.as_deref());
        self.seen = Some(key);
        self.seen_generation = self.generation;
        let (sender, receiver) = mpsc::sync_channel(1);
        let (data_dir, folder, wake) = (data_dir.to_path_buf(), folder, ctx.clone());
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

impl MonitorApp {
    /// Every frame (see [`GeoipState::sync`]).
    pub(in crate::app) fn geoip_sync(&mut self, ctx: &egui::Context) {
        let installed = self
            .snapshot
            .analysis_tools
            .iter()
            .find(|tool| tool.id == geoip::TOOL_ID)
            .and_then(|tool| tool.installed.clone());
        self.routes
            .geoip
            .sync(ctx, &self.options.data_dir, installed);
    }

    /// The Network lookup page's database section.
    pub(in crate::app) fn geoip_section(&mut self, ui: &mut egui::Ui) {
        theme::section(ui, "IP geolocation database (TShark)");
        ui.add(
            egui::Label::new(
                "TShark needs .mmdb databases to fill Country and Organization. Older \
                 GeoIP.dat files (such as /usr/share/GeoIP on Debian) do not work with \
                 TShark 4. Antinomie hands its databases to its own TShark runs only and \
                 never changes your Wireshark settings.",
            )
            .wrap(),
        );
        ui.add_space(4.0);
        tools_page::geoip_status(ui, self.routes.geoip.status());
        ui.add_space(6.0);
        let tool = self
            .snapshot
            .analysis_tools
            .iter()
            .find(|tool| tool.id == geoip::TOOL_ID)
            .cloned();
        let managed = self
            .routes
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
        tools_page::geoip_attribution(ui);
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
                    !busy && self.routes.geoip.update.is_none(),
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
        if outbound && managed.is_some() && !self.routes.geoip.asked_once {
            self.routes.geoip.asked_once = true;
            self.routes.geoip.start_check(&ctx, &curl);
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Monthly refresh")
                    .strong()
                    .color(theme::heading()),
            );
            let idle = self.routes.geoip.checking.is_none() && self.routes.geoip.update.is_none();
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
                self.routes.geoip.start_check(&ctx, &curl);
            }
            if self.routes.geoip.checking.is_some() {
                ui.spinner();
            }
        });
        if !outbound {
            hint_line(
                ui,
                "Checking for a newer month needs Settings > Detection > Allow outbound catalog and rule downloads.",
            );
        }
        match self.routes.geoip.latest.clone() {
            Some(Ok(latest)) => {
                let installed = managed.map(|m| m.month.as_str());
                if installed.is_some_and(|month| month >= latest.month.as_str()) {
                    ui.weak(format!("Up to date: {} is the newest month.", latest.month));
                } else if self.routes.geoip.update.is_none() {
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
                            self.routes.geoip.start_update(&ctx, &curl, &data_dir, latest.month);
                        }
                    });
                }
            }
            Some(Err(error)) => {
                crate::activity::warning(ui, format!("Could not ask DB-IP: {error}"));
            }
            None => {}
        }
        if let Some(update) = &self.routes.geoip.update {
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
                    crate::values::short_size(update.received),
                    crate::values::short_size(update.total)
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
        if let Some(error) = &self.routes.geoip.update_error {
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
            .routes
            .geoip
            .folder
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
                        .desired_width(crate::theme::edit_width(width))
                        .font(egui::TextStyle::Monospace)
                        .hint_text(crate::theme::placeholder(
                            ui,
                            "Folder with GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb",
                        )),
                )
                .changed()
            {
                let chosen = (!text.trim().is_empty()).then(|| crate::folders::user_path(&text));
                self.routes.geoip.set_folder(&self.options.data_dir, chosen);
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
                self.routes.geoip.folder.is_some(),
            ) {
                self.routes.geoip.set_folder(&self.options.data_dir, None);
            }
        });
        hint_line(
            ui,
            "A folder with your own MaxMind GeoLite2 or GeoIP2 .mmdb files: a Country or City \
             database and an ASN database. MaxMind requires a free account to download them, \
             so Antinomie cannot fetch them for you; the DB-IP Lite install needs no account. \
             The files are read where they are, not copied.",
        );
    }
}

fn hint_line(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap());
}
