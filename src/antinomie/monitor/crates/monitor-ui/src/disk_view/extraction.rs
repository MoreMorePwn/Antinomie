// SPDX-License-Identifier: GPL-3.0-only
//! Extracting a guest file to the host: the reader writes it, the parent
//! gives it a sanitized private name, and what happens next is the intent.
//! Nothing is ever executed; the viewer, Save to host, Open with and Static
//! Analysis all work on the extracted copy.
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::reader::{DiskEntry, ExtractReceipt};
use std::{
    collections::BTreeSet,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver},
};

/// Largest file extracted after the user confirmed going over the limit.
const CONFIRMED_CAP: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Intent {
    View,
    Save,
    OpenWith,
    Analyze,
}

pub(super) struct Saving {
    receiver: Receiver<Result<Option<PathBuf>, String>>,
}

#[derive(Default)]
pub(super) struct State {
    /// Paths the user confirmed extracting over the limit.
    pub allow_large: BTreeSet<String>,
    /// A request waiting for the user to confirm a file over the limit.
    pub large: Option<(String, u64, Intent)>,
    /// Extractions in flight, by guest path.
    pub running: BTreeSet<String>,
    saving: Option<Saving>,
    /// A copy waiting for the user to confirm opening it elsewhere.
    pub confirm_open: Option<PathBuf>,
}

impl DiskView {
    pub(super) fn menu(
        &mut self,
        ui: &egui::Ui,
        path: String,
        entry: DiskEntry,
        choice: tree::Choice,
    ) {
        if self
            .selection
            .as_ref()
            .is_none_or(|selection| selection.path != path)
        {
            self.select(path.clone());
        }
        match choice {
            tree::Choice::CopyPath => ui.ctx().copy_text(path),
            tree::Choice::ExtractToView => self.request_extract(path, entry.size, Intent::View),
            tree::Choice::SaveToHost => self.request_extract(path, entry.size, Intent::Save),
            tree::Choice::OpenWith => self.request_extract(path, entry.size, Intent::OpenWith),
            tree::Choice::HandToAnalysis => {
                self.request_extract(path, entry.size, Intent::Analyze);
            }
        }
    }

    /// Ask the reader to extract `path` (of `size` bytes), within the limits.
    pub(super) fn request_extract(&mut self, path: String, size: u64, intent: Intent) {
        if intent == Intent::View && size > VIEW_CAP {
            self.status = Some((
                format!(
                    "{} is {}: files over {} are Save-to-host only, not loaded into the viewer.",
                    display_name(&path),
                    format_size(size),
                    format_size(VIEW_CAP)
                ),
                true,
            ));
            return;
        }
        let cap = self.settings.extract_cap();
        let mut max_len = cap;
        if size > cap {
            if !self.extraction.allow_large.contains(&path) {
                self.extraction.large = Some((path, size, intent));
                return;
            }
            max_len = CONFIRMED_CAP;
            if size > CONFIRMED_CAP {
                self.status = Some((
                    format!(
                        "{} is larger than the {} hard limit.",
                        display_name(&path),
                        format_size(CONFIRMED_CAP)
                    ),
                    true,
                ));
                return;
            }
            let free = self.bound.as_ref().and_then(|view| {
                view.extract_dir
                    .ancestors()
                    .find(|directory| directory.is_dir())
                    .and_then(|directory| {
                        antinomie_monitor_core::disks::measure::free_space(directory).ok()
                    })
                    .map(|free| (free, view.extract_dir.clone()))
            });
            if let Some((free, directory)) = free {
                if free < size.saturating_add(64 * 1024 * 1024) {
                    self.status = Some((
                        format!(
                            "Not enough free space for {}: {} available in {}.",
                            format_size(size),
                            format_size(free),
                            directory.display()
                        ),
                        true,
                    ));
                    return;
                }
            }
        }
        if !self.extraction.running.insert(path.clone()) {
            return;
        }
        self.status = None;
        self.queue_search(
            Purpose::Extract {
                path: path.clone(),
                intent,
            },
            DiskRequest::Extract {
                path: path.clone(),
                max_len,
            },
            Some(path),
        );
    }

    pub(super) fn extraction_done(
        &mut self,
        path: String,
        intent: Intent,
        receipt: Result<ExtractReceipt, String>,
        placed: Option<Result<PathBuf, String>>,
    ) {
        self.extraction.running.remove(&path);
        let (receipt, host) = match (receipt, placed) {
            (Ok(receipt), Some(Ok(host))) => (receipt, host),
            (Ok(_), Some(Err(error))) | (Err(error), _) => {
                self.status = Some((format!("Extracting {}: {error}", display_name(&path)), true));
                return;
            }
            (Ok(_), None) => {
                self.status = Some(("The extracted file was not placed.".into(), true));
                return;
            }
        };
        self.extracted.push(Extracted {
            guest_path: path.clone(),
            host_path: host.clone(),
            size: receipt.size,
            sha256: receipt.sha256.clone(),
        });
        self.status = Some((
            format!(
                "Extracted {} ({}) to {}: private, never executable.",
                display_name(&path),
                format_size(receipt.size),
                host.display()
            ),
            false,
        ));
        self.status_name = Some(display_name(&path));
        match intent {
            Intent::View => match read_for_view(&host) {
                Ok(bytes) => {
                    self.action = Some(DiskAction::ViewBytes {
                        key: host.display().to_string(),
                        title: format!("Disk file {}", display_name(&path)),
                        bytes,
                    });
                }
                Err(error) => self.status = Some((error, true)),
            },
            Intent::Save => self.start_save(&path, &host),
            Intent::OpenWith => self.extraction.confirm_open = Some(host),
            Intent::Analyze => self.action = Some(DiskAction::Analyze(host)),
        }
    }

    /// The last extraction or save as a line: a file name in it in bold, and
    /// a button that clears it. Failures go to the toasts instead.
    pub(super) fn status_line(&mut self, ui: &mut egui::Ui) {
        crate::toasts::take_failure(ui.ctx(), &mut self.status);
        let Some((message, _)) = &self.status else {
            return;
        };
        let font = egui::TextStyle::Body.resolve(ui.style());
        let color = theme::good();
        let mut job = egui::text::LayoutJob::default();
        let name = self
            .status_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .and_then(|name| message.find(name).map(|at| (at, name.len())));
        let plain = |font: &egui::FontId| egui::text::TextFormat::simple(font.clone(), color);
        match name {
            Some((at, len)) => {
                job.append(&message[..at], 0.0, plain(&font));
                job.append(&message[at..at + len], 0.0, plain(&theme::bold_font(ui)));
                job.append(&message[at + len..], 0.0, plain(&font));
            }
            None => job.append(message, 0.0, plain(&font)),
        }
        let mut close = false;
        ui.horizontal_top(|ui| {
            close = ui
                .add(
                    egui::Button::new(
                        egui::RichText::new(egui_phosphor::regular::X).color(theme::muted()),
                    )
                    .frame(false),
                )
                .on_hover_text("Dismiss")
                .clicked();
            ui.add(egui::Label::new(job).wrap());
        });
        if close {
            self.status = None;
            self.status_name = None;
        }
    }

    fn start_save(&mut self, guest_path: &str, host: &Path) {
        let (sender, receiver) = mpsc::channel();
        let leaf = host
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let from = host.to_path_buf();
        let _ = guest_path;
        std::thread::spawn(move || {
            let chosen = Command::new("zenity")
                .args([
                    "--file-selection",
                    "--save",
                    "--confirm-overwrite",
                    "--title=Save the guest file to the host",
                ])
                .arg(format!("--filename={leaf}"))
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output();
            let result = match chosen {
                Err(error) => Err(format!(
                    "File chooser (zenity) unavailable: {error}. The extracted copy is at {}",
                    from.display()
                )),
                Ok(output) if !output.status.success() => Ok(None),
                Ok(output) => {
                    let text = String::from_utf8_lossy(&output.stdout);
                    let destination = PathBuf::from(text.trim_end_matches('\n'));
                    if destination.as_os_str().is_empty() || !destination.is_absolute() {
                        Ok(None)
                    } else {
                        std::fs::copy(&from, &destination)
                            .and_then(|_| {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(
                                    &destination,
                                    std::fs::Permissions::from_mode(0o600),
                                )
                            })
                            .map(|()| Some(destination.clone()))
                            .map_err(|error| format!("{}: {error}", destination.display()))
                    }
                }
            };
            let _ = sender.send(result);
        });
        self.extraction.saving = Some(Saving { receiver });
    }

    /// Finish a Save to host when its chooser closed.
    pub(super) fn poll_save(&mut self, ctx: &egui::Context) {
        let Some(saving) = &self.extraction.saving else {
            return;
        };
        match saving.receiver.try_recv() {
            Ok(Ok(Some(destination))) => {
                self.status = Some((
                    format!("Saved to {} (mode 0600).", destination.display()),
                    false,
                ));
                self.extraction.saving = None;
            }
            Ok(Ok(None)) => {
                self.extraction.saving = None;
            }
            Ok(Err(error)) => {
                self.status = Some((error, true));
                self.extraction.saving = None;
            }
            Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(200)),
            Err(mpsc::TryRecvError::Disconnected) => self.extraction.saving = None,
        }
    }
}

/// The bytes of an extracted file for the viewer, bounded.
fn read_for_view(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(VIEW_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > VIEW_CAP {
        return Err("The file is larger than the viewer limit.".into());
    }
    Ok(bytes)
}
