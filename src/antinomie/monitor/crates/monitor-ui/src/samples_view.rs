//! Tools → Malware samples: search MalwareBazaar, download samples (kept in
//! their encrypted archives) and send them into the running VM, optionally
//! running them there. Nothing is run or unpacked on the host.
use crate::theme::{self, ValueKind};
use antinomie_monitor_core::{
    samples::{self, Query, SampleInfo, StoredSample},
    ExecRequest,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

pub(crate) const WINDOW_ID: &str = "malware_samples";

pub(crate) struct SamplesContext<'a> {
    pub data_dir: &'a Path,
    pub curl: &'a Path,
    /// The selected VM is running: samples can be sent into it.
    pub running: bool,
    pub vm_name: Option<&'a str>,
    /// The selected VM reaches the network.
    pub nat: bool,
    pub font_size: f32,
}

pub(crate) enum SamplesAction {
    /// Send a downloaded sample into the guest; run it after if `run` is set.
    Push {
        sha256: String,
        destination: String,
        run: Option<ExecRequest>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Family,
    Tag,
    FileType,
    Hash,
    Recent,
}

impl Kind {
    const ALL: [Kind; 5] = [
        Kind::Family,
        Kind::Tag,
        Kind::FileType,
        Kind::Hash,
        Kind::Recent,
    ];
    fn label(self) -> &'static str {
        match self {
            Kind::Family => "Family",
            Kind::Tag => "Tag",
            Kind::FileType => "File type",
            Kind::Hash => "Hash",
            Kind::Recent => "Newest",
        }
    }
    fn hint(self) -> &'static str {
        match self {
            Kind::Family => "XorDDoS, Mirai, Kinsing…",
            Kind::Tag => "elf, x86-64, botnet…",
            Kind::FileType => "elf",
            Kind::Hash => "SHA-256, SHA-1 or MD5",
            Kind::Recent => "the latest 100 samples",
        }
    }
}

pub(crate) struct SamplesView {
    pub(crate) open: bool,
    key: String,
    key_saved: bool,
    key_loaded: bool,
    kind: Kind,
    text: String,
    elf_only: bool,
    results: Vec<SampleInfo>,
    searching: Option<Receiver<Result<Vec<SampleInfo>, String>>>,
    downloads: BTreeMap<String, Receiver<Result<StoredSample, String>>>,
    stored: Option<Vec<StoredSample>>,
    /// Run pushed samples as root instead of the guest user.
    as_root: bool,
    status: Option<(String, bool)>,
    /// The upload request and the run that follows it.
    pending: Option<(u64, Option<ExecRequest>)>,
    awaiting: Option<Option<ExecRequest>>,
}

impl Default for SamplesView {
    fn default() -> Self {
        Self {
            open: false,
            key: String::new(),
            key_saved: false,
            key_loaded: false,
            kind: Kind::Family,
            text: String::new(),
            elf_only: true,
            results: Vec::new(),
            searching: None,
            downloads: BTreeMap::new(),
            stored: None,
            as_root: false,
            status: None,
            pending: None,
            awaiting: None,
        }
    }
}

fn format_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

/// A guest path for a sample: its hash prefix and a safe form of its name.
fn guest_path(sample: &SampleInfo) -> String {
    let name: String = sample
        .file_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    format!(
        "/tmp/{}-{}",
        &sample.sha256_hash[..12.min(sample.sha256_hash.len())],
        if name.is_empty() {
            "sample".into()
        } else {
            name
        }
    )
}

impl SamplesView {
    /// The app sent the upload as request `id`.
    pub(crate) fn sent(&mut self, id: u64) {
        if let Some(run) = self.awaiting.take() {
            self.pending = Some((id, run));
        }
    }

    /// A request finished; returns the run to start after a successful push.
    pub(crate) fn complete(
        &mut self,
        id: u64,
        success: bool,
        message: &str,
    ) -> Option<ExecRequest> {
        let (pending, run) = self.pending.take_if(|(pending, _)| *pending == id)?;
        let _ = pending;
        self.stored = None;
        self.status = Some(if success {
            (format!("Sent into the VM: {message}"), false)
        } else {
            (format!("Could not send the sample: {message}"), true)
        });
        run.filter(|_| success)
    }

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(found) = self.searching.as_ref().and_then(|r| r.try_recv().ok()) {
            self.searching = None;
            match found {
                Ok(found) => {
                    self.status = Some((format!("{} samples found", found.len()), false));
                    self.results = found;
                }
                Err(error) => self.status = Some((error, true)),
            }
        }
        let mut finished = Vec::new();
        self.downloads
            .retain(|hash, receiver| match receiver.try_recv() {
                Ok(result) => {
                    finished.push((hash.clone(), result));
                    false
                }
                Err(mpsc::TryRecvError::Empty) => true,
                Err(mpsc::TryRecvError::Disconnected) => false,
            });
        for (hash, result) in finished {
            self.stored = None;
            self.status = Some(match result {
                Ok(sample) => (
                    format!(
                        "Downloaded {} ({}), kept encrypted",
                        sample.info.file_name,
                        sample.info.file_arch.as_deref().unwrap_or("not an ELF")
                    ),
                    false,
                ),
                Err(error) => (format!("{}: {error}", &hash[..12.min(hash.len())]), true),
            });
        }
        if self.searching.is_some() || !self.downloads.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }

    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        cx: &SamplesContext<'_>,
    ) -> Option<SamplesAction> {
        if !self.open {
            return None;
        }
        if !self.key_loaded {
            self.key = samples::api_key(cx.data_dir);
            self.key_saved = !self.key.is_empty();
            self.key_loaded = true;
        }
        self.poll(ctx);
        let stored = self
            .stored
            .get_or_insert_with(|| samples::stored(cx.data_dir))
            .clone();
        let mut action = None;
        let mut open = true;
        egui::Window::new("Malware samples")
            .id(egui::Id::new(WINDOW_ID))
            .collapsible(false)
            .resizable(true)
            .default_width(900.0)
            .default_height(640.0)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .open(&mut open)
            .show(ctx, |ui| {
                self.warning(ui, cx);
                ui.add_space(6.0);
                self.key_row(ui, cx);
                ui.add_space(6.0);
                theme::section(ui, "Search MalwareBazaar");
                self.search_row(ui, cx);
                ui.add_space(4.0);
                let half = (ui.available_height() / 2.0).max(140.0);
                ui.allocate_ui(egui::vec2(ui.available_width(), half), |ui| {
                    self.results_table(ui, cx, &stored);
                });
                ui.add_space(6.0);
                theme::section(ui, "Downloaded");
                if let Some(next) = self.stored_list(ui, cx, &stored) {
                    action = Some(next);
                }
            });
        if !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
        }
        action
    }

    fn warning(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        egui::Frame::new()
            .fill(theme::raised())
            .corner_radius(6.0)
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(egui_phosphor::regular::BIOHAZARD).color(theme::warn()));
                    ui.label(
                        RichText::new(
                            "Live malware. Samples stay in MalwareBazaar's encrypted archives \
                             in the data folder and are decrypted only in memory, to be sent \
                             into the VM. Nothing is run on this computer. Use a VM you can \
                             throw away, or take a snapshot first.",
                        )
                        .color(theme::text()),
                    );
                });
                if cx.nat {
                    ui.colored_label(
                        theme::warn(),
                        "NAT is on for this VM: a sample run there can reach your network and \
                         the Internet.",
                    );
                }
                if let Some((message, error)) = &self.status {
                    ui.colored_label(
                        if *error {
                            theme::error()
                        } else {
                            theme::good()
                        },
                        message,
                    );
                }
            });
    }

    fn key_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        ui.horizontal(|ui| {
            ui.label("MalwareBazaar API key");
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.key)
                    .password(true)
                    .hint_text("free key from abuse.ch")
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(320.0),
            );
            if edit.changed() {
                self.key_saved = false;
            }
            if ui
                .add_enabled(!self.key_saved, egui::Button::new("Save key"))
                .on_hover_text("Kept in the data folder, readable only by you")
                .clicked()
            {
                match samples::save_api_key(cx.data_dir, &self.key) {
                    Ok(()) => {
                        self.key_saved = true;
                        self.status = Some(("API key saved".into(), false));
                    }
                    Err(error) => self.status = Some((error, true)),
                }
            }
            ui.hyperlink_to(
                format!("Get a key {}", egui_phosphor::regular::ARROW_SQUARE_OUT),
                samples::BAZAAR_KEYS,
            );
        });
    }

    fn search_row(&mut self, ui: &mut egui::Ui, cx: &SamplesContext<'_>) {
        let mut search = None;
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("samples_kind")
                .selected_text(self.kind.label())
                .show_ui(ui, |ui| {
                    for kind in Kind::ALL {
                        ui.selectable_value(&mut self.kind, kind, kind.label());
                    }
                });
            let edit = ui.add_enabled(
                self.kind != Kind::Recent,
                egui::TextEdit::singleline(&mut self.text)
                    .hint_text(self.kind.hint())
                    .margin(theme::TEXT_EDIT_MARGIN)
                    .desired_width(260.0),
            );
            let enter = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            ui.checkbox(&mut self.elf_only, "ELF only")
                .on_hover_text("Linux programs: what the VMs can run");
            let ready = self.searching.is_none()
                && (self.kind == Kind::Recent || !self.text.trim().is_empty());
            if (ui
                .add_enabled(
                    ready,
                    egui::Button::new(
                        RichText::new(format!(
                            "{} Search",
                            egui_phosphor::regular::MAGNIFYING_GLASS
                        ))
                        .color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
                .clicked()
                || (enter && ready))
                && ready
            {
                search = Some(match self.kind {
                    Kind::Family => Query::Signature(self.text.clone()),
                    Kind::Tag => Query::Tag(self.text.clone()),
                    Kind::FileType => Query::FileType(self.text.clone()),
                    Kind::Hash => Query::Hash(self.text.clone()),
                    Kind::Recent => Query::Recent,
                });
            }
            if self.searching.is_some() {
                ui.spinner();
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Families that run on x86-64 Linux:").color(theme::muted()));
            for (name, about) in samples::STARTERS {
                if ui
                    .add_enabled(self.searching.is_none(), egui::Button::new(*name).small())
                    .on_hover_text(*about)
                    .clicked()
                {
                    self.kind = Kind::Family;
                    self.text = (*name).into();
                    search = Some(Query::Signature((*name).into()));
                }
            }
        });
        if let Some(query) = search {
            let (sender, receiver) = mpsc::channel();
            let (curl, key) = (cx.curl.to_path_buf(), self.key.clone());
            std::thread::spawn(move || {
                let _ = sender.send(samples::search(&curl, &key, &query, 200));
            });
            self.searching = Some(receiver);
            self.status = None;
        }
    }

    fn results_table(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
    ) {
        let shown: Vec<&SampleInfo> = self
            .results
            .iter()
            .filter(|sample| !self.elf_only || sample.is_elf())
            .collect();
        if shown.is_empty() {
            ui.colored_label(
                theme::muted(),
                if self.results.is_empty() {
                    "Search by family, tag, file type or hash."
                } else {
                    "No ELF samples in this search: untick ELF only to see the others."
                },
            );
            return;
        }
        let mono = theme::mono(cx.font_size - 1.0);
        let row_height = theme::row_height(cx.font_size);
        let mut download = None;
        TableBuilder::new(ui)
            .id_salt("samples_results")
            .striped(true)
            .resizable(true)
            .auto_shrink([false, false])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(220.0).clip(true))
            .column(Column::initial(110.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(80.0))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::remainder().at_least(110.0))
            .header(row_height, |mut header| {
                for name in ["File", "Family", "Type", "Size", "Tags", "First seen", ""] {
                    header.col(|ui| {
                        ui.label(RichText::new(name).strong().color(theme::heading()));
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, shown.len(), |mut row| {
                    let sample = shown[row.index()];
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&sample.file_name).font(mono.clone()))
                                .truncate(),
                        )
                        .on_hover_text(&sample.sha256_hash);
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(sample.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                    });
                    row.col(|ui| {
                        ui.label(&sample.file_type);
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(format_size(sample.file_size))
                                .color(theme::value(ValueKind::Number)),
                        );
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(sample.tags.join(", ")).truncate())
                            .on_hover_text(sample.tags.join(", "));
                    });
                    row.col(|ui| {
                        ui.colored_label(theme::muted(), &sample.first_seen);
                    });
                    row.col(|ui| {
                        let hash = &sample.sha256_hash;
                        if stored.iter().any(|s| &s.info.sha256_hash == hash) {
                            ui.colored_label(theme::good(), "Downloaded");
                        } else if self.downloads.contains_key(hash) {
                            ui.spinner();
                        } else if ui
                            .button(format!(
                                "{} Download",
                                egui_phosphor::regular::DOWNLOAD_SIMPLE
                            ))
                            .clicked()
                        {
                            download = Some(sample.clone());
                        }
                    });
                });
            });
        if let Some(sample) = download {
            let (sender, receiver) = mpsc::channel();
            let (curl, key, data): (PathBuf, String, PathBuf) =
                (cx.curl.into(), self.key.clone(), cx.data_dir.into());
            let hash = sample.sha256_hash.clone();
            std::thread::spawn(move || {
                let _ = sender.send(samples::download(&curl, &key, &data, &sample));
            });
            self.downloads.insert(hash, receiver);
        }
    }

    fn stored_list(
        &mut self,
        ui: &mut egui::Ui,
        cx: &SamplesContext<'_>,
        stored: &[StoredSample],
    ) -> Option<SamplesAction> {
        let mut action = None;
        let mut delete = None;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Run as").color(theme::muted()));
            ui.selectable_value(&mut self.as_root, false, "guest user");
            ui.selectable_value(&mut self.as_root, true, "root");
            if let Some(name) = cx.vm_name {
                ui.colored_label(theme::muted(), format!("· VM: {name}"));
            }
            if !cx.running {
                ui.colored_label(theme::warn(), "· start the VM to send samples into it");
            }
        });
        if stored.is_empty() {
            ui.colored_label(theme::muted(), "No samples downloaded yet.");
            return None;
        }
        let pending = self.pending.is_some() || self.awaiting.is_some();
        egui::ScrollArea::vertical()
            .id_salt("samples_stored")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for sample in stored {
                    let info = &sample.info;
                    let arch = info.file_arch.as_deref();
                    let runs_here = arch.is_some_and(|a| a == "x86_64");
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&info.file_name).font(theme::mono(cx.font_size - 1.0)))
                            .on_hover_text(format!(
                                "SHA-256 {}\nFrom {} · first seen {}\nSent into VMs {} times",
                                info.sha256_hash,
                                sample.source,
                                info.first_seen,
                                sample.pushes.len()
                            ));
                        ui.label(
                            RichText::new(info.signature.as_deref().unwrap_or("-"))
                                .color(theme::value(ValueKind::Name)),
                        );
                        ui.label(
                            RichText::new(arch.unwrap_or("not an ELF")).color(if runs_here {
                                theme::good()
                            } else {
                                theme::warn()
                            }),
                        )
                        .on_hover_text(if runs_here {
                            "Runs in Antinomie's x86-64 guests"
                        } else {
                            "Built for another processor or not a Linux program: it will not run in the x86-64 guests"
                        });
                        ui.colored_label(theme::muted(), format_size(info.file_size));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .button(RichText::new("Delete").color(theme::error()))
                                .clicked()
                            {
                                delete = Some(info.sha256_hash.clone());
                            }
                            if ui
                                .button(egui_phosphor::regular::COPY)
                                .on_hover_text("Copy the SHA-256")
                                .clicked()
                            {
                                ui.ctx().copy_text(info.sha256_hash.clone());
                            }
                            let can = cx.running && !pending;
                            let destination = guest_path(info);
                            if ui
                                .add_enabled(can && runs_here, egui::Button::new("Send and run"))
                                .on_hover_text(format!(
                                    "Send to {destination} and run it, recorded like any program"
                                ))
                                .on_disabled_hover_text(if runs_here {
                                    "Start the VM first"
                                } else {
                                    "Only x86-64 Linux programs run in the guests"
                                })
                                .clicked()
                            {
                                let uid = if self.as_root { 0 } else { 1000 };
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination: destination.clone(),
                                    run: Some(ExecRequest {
                                        path: destination.clone(),
                                        uid,
                                        gid: uid,
                                        cwd: "/tmp".into(),
                                        ..ExecRequest::default()
                                    }),
                                });
                            }
                            if ui
                                .add_enabled(can, egui::Button::new("Send to VM"))
                                .on_hover_text(format!(
                                    "Send to {destination} without running it (executable)"
                                ))
                                .on_disabled_hover_text("Start the VM first")
                                .clicked()
                            {
                                action = Some(SamplesAction::Push {
                                    sha256: info.sha256_hash.clone(),
                                    destination,
                                    run: None,
                                });
                            }
                        });
                    });
                    ui.separator();
                }
            });
        if let Some(hash) = delete {
            self.status = Some(match samples::delete(cx.data_dir, &hash) {
                Ok(()) => ("Sample deleted".into(), false),
                Err(error) => (error, true),
            });
            self.stored = None;
        }
        if let Some(SamplesAction::Push { run, .. }) = &action {
            self.awaiting = Some(run.clone());
        }
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_paths_are_safe_and_unique_per_sample() {
        let sample = SampleInfo {
            sha256_hash: "ab".repeat(32),
            file_name: "../evil name;rm.elf".into(),
            ..SampleInfo::default()
        };
        assert_eq!(guest_path(&sample), "/tmp/abababababab-.._evil_name_rm.elf");
    }

    #[test]
    fn a_successful_push_starts_its_run_once() {
        let mut view = SamplesView::default();
        let run = ExecRequest {
            path: "/tmp/x".into(),
            ..ExecRequest::default()
        };
        view.awaiting = Some(Some(run.clone()));
        view.sent(7);
        assert!(view.complete(6, true, "other").is_none());
        assert_eq!(
            view.complete(7, true, "uploaded").map(|r| r.path),
            Some(run.path)
        );
        assert!(view.complete(7, true, "again").is_none());
        view.awaiting = Some(Some(ExecRequest::default()));
        view.sent(8);
        assert!(view.complete(8, false, "no room").is_none());
    }
}
