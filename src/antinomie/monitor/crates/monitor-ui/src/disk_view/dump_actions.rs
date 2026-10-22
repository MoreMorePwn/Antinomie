// SPDX-License-Identifier: MIT
//! What the tab does with a saved dump on the host: import a raw ext4 image,
//! verify the recorded SHA-256, and save the image as a sparse raw or a qcow2
//! file. Each runs on its own thread; the frame only polls a channel.
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::{
    dump,
    export::{self, ExportFormat, Exported},
    DiskSourceSpec,
};
use std::{
    process::{Child, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
};

/// The Import image… dialog.
pub(super) struct Import {
    pub path: String,
    pub picker: Option<Child>,
    pub error: Option<String>,
}

/// A partition save waiting for the host file to be chosen.
pub(super) struct PartitionSave {
    source: DiskSourceSpec,
    partition: u32,
    receiver: Receiver<Result<Option<PathBuf>, String>>,
}

impl PartitionSave {
    #[cfg(test)]
    pub(super) fn new(
        source: DiskSourceSpec,
        partition: u32,
        receiver: Receiver<Result<Option<PathBuf>, String>>,
    ) -> Self {
        Self {
            source,
            partition,
            receiver,
        }
    }
}

/// A SHA-256 check in progress.
pub(super) struct Verify {
    pub id: String,
    receiver: Receiver<Result<String, String>>,
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
    recorded: Option<String>,
}

/// What a finished check found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verified {
    /// The image hashes to the recorded digest.
    Matches(String),
    /// It does not.
    Differs {
        computed: String,
        recorded: String,
    },
    /// Nothing was recorded; this is what it hashes to now.
    Computed(String),
    Failed(String),
}

/// A save of the image to the host in progress.
pub(super) struct ImageSave {
    pub id: String,
    pub format: ExportFormat,
    receiver: Receiver<Result<Option<Exported>, String>>,
    cancel: Arc<AtomicBool>,
    percent: Arc<AtomicU32>,
    /// The chooser closed with a file: the copy is running.
    started: Arc<AtomicBool>,
}

impl DiskView {
    /// Check the image against its recorded SHA-256 (or compute it).
    pub(super) fn start_verify(&mut self, ctx: &egui::Context, dump: &DiskDump, image: PathBuf) {
        if self.verify.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicU64::new(0));
        let total = Arc::new(AtomicU64::new(0));
        let (flag, progress, size, repaint) =
            (cancel.clone(), done.clone(), total.clone(), ctx.clone());
        thread::spawn(move || {
            let result = dump::sha256_file(&image, &flag, |read, all| {
                progress.store(read, Ordering::Relaxed);
                size.store(all, Ordering::Relaxed);
            });
            let _ = sender.send(result);
            repaint.request_repaint();
        });
        self.verified.remove(&dump.id);
        self.verify = Some(Verify {
            id: dump.id.clone(),
            receiver,
            cancel,
            done,
            total,
            recorded: dump.sha256.clone(),
        });
    }

    /// Save a dump's image: the chooser, then `qemu-img convert` to the file.
    pub(super) fn start_save_image(
        &mut self,
        ctx: &egui::Context,
        dump: &DiskDump,
        qemu_img: &Path,
        format: ExportFormat,
    ) {
        self.spawn_save(ctx, dump, qemu_img, format, |suggestion| {
            choose_destination(suggestion)
        });
    }

    /// [`Self::start_save_image`] with the way the destination is chosen
    /// given (a file chooser; a fixed path in the tests).
    pub(super) fn spawn_save(
        &mut self,
        ctx: &egui::Context,
        dump: &DiskDump,
        qemu_img: &Path,
        format: ExportFormat,
        choose: impl FnOnce(&str) -> Result<Option<PathBuf>, String> + Send + 'static,
    ) {
        if self.saving_image.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let percent = Arc::new(AtomicU32::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let (flag, shared, begun, repaint) = (
            cancel.clone(),
            percent.clone(),
            started.clone(),
            ctx.clone(),
        );
        let (source, qemu_img) = (dump.path(), qemu_img.to_path_buf());
        let suggestion = suggested_name(dump, format);
        thread::spawn(move || {
            let result = choose(&suggestion).and_then(|chosen| {
                let Some(destination) = chosen else {
                    return Ok(None);
                };
                begun.store(true, Ordering::Relaxed);
                repaint.request_repaint();
                export::export(&qemu_img, &source, &destination, format, &flag, |value| {
                    shared.store(value.to_bits(), Ordering::Relaxed);
                })
                .map(Some)
            });
            let _ = sender.send(result);
            repaint.request_repaint();
        });
        self.saving_image = Some(ImageSave {
            id: dump.id.clone(),
            format,
            receiver,
            cancel,
            percent,
            started,
        });
    }

    /// Ask where to save partition `index` of the picked source.
    pub(super) fn save_partition(&mut self, ctx: &egui::Context, index: u32) {
        if self.partition_save.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        let repaint = ctx.clone();
        thread::spawn(move || {
            let _ = sender.send(choose_destination(&format!("partition-{index}.bin")));
            repaint.request_repaint();
        });
        self.partition_save = Some(PartitionSave {
            source: self.pick.source.clone(),
            partition: index,
            receiver,
        });
    }

    /// Take the results of the host-side actions.
    pub(super) fn poll_dump_actions(&mut self, ctx: &egui::Context) {
        self.poll_picker();
        if let Some(save) = &self.partition_save {
            match save.receiver.try_recv() {
                Ok(result) => {
                    let (source, partition) = (save.source.clone(), save.partition);
                    self.partition_save = None;
                    match result {
                        Ok(Some(path)) => {
                            self.wait_for(false);
                            self.action = Some(DiskAction::SavePartition {
                                source,
                                partition,
                                path,
                            });
                        }
                        Ok(None) => {}
                        Err(error) => self.status = Some((error, true)),
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
                Err(mpsc::TryRecvError::Disconnected) => self.partition_save = None,
            }
        }
        if let Some(verify) = &self.verify {
            match verify.receiver.try_recv() {
                Ok(result) => {
                    let id = verify.id.clone();
                    let recorded = verify.recorded.clone();
                    self.verify = None;
                    match (result, recorded) {
                        (Ok(computed), Some(recorded)) if computed == recorded => {
                            self.verified.insert(id, Verified::Matches(computed));
                        }
                        (Ok(computed), Some(recorded)) => {
                            self.verified
                                .insert(id, Verified::Differs { computed, recorded });
                        }
                        (Ok(computed), None) => {
                            self.verified.insert(id, Verified::Computed(computed));
                        }
                        (Err(error), _) if error == "cancelled" => {}
                        (Err(error), _) => {
                            self.verified.insert(id, Verified::Failed(error));
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
                Err(mpsc::TryRecvError::Disconnected) => self.verify = None,
            }
        }
        if let Some(saving) = &self.saving_image {
            match saving.receiver.try_recv() {
                Ok(result) => {
                    let format = saving.format;
                    self.saving_image = None;
                    self.status = match result {
                        Ok(Some(done)) => Some((
                            format!(
                                "Saved {} to {}: {} on disk of {}.",
                                format.label().to_lowercase(),
                                done.path.display(),
                                format_size(done.allocated),
                                format_size(done.size)
                            ),
                            false,
                        )),
                        Ok(None) => None,
                        Err(error) if error == "cancelled" => {
                            Some(("Saving the image was cancelled.".into(), false))
                        }
                        Err(error) => Some((format!("Saving the image: {error}"), true)),
                    };
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(200));
                }
                Err(mpsc::TryRecvError::Disconnected) => self.saving_image = None,
            }
        }
    }

    /// Progress and Cancel of a running check or save, for the Details dock.
    pub(super) fn host_progress(&mut self, ui: &mut egui::Ui, id: &str) {
        if let Some(verify) = self.verify.as_ref().filter(|verify| verify.id == id) {
            let total = verify.total.load(Ordering::Relaxed).max(1);
            let fraction = verify.done.load(Ordering::Relaxed) as f32 / total as f32;
            ui.horizontal(|ui| {
                theme::spinner(ui);
                ui.add(
                    egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                        .desired_width(220.0)
                        .text(format!("Hashing {:.0} %", fraction * 100.0)),
                );
                if ui.button("Cancel").clicked() {
                    verify.cancel.store(true, Ordering::Relaxed);
                }
            });
        }
        if let Some(saving) = self.saving_image.as_ref().filter(|saving| saving.id == id) {
            let fraction = f32::from_bits(saving.percent.load(Ordering::Relaxed)) / 100.0;
            ui.horizontal(|ui| {
                theme::spinner(ui);
                if saving.started.load(Ordering::Relaxed) {
                    ui.add(
                        egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                            .desired_width(220.0)
                            .text(format!("Saving {:.0} %", fraction * 100.0)),
                    );
                } else {
                    ui.colored_label(theme::muted(), "Choose where to save the image…");
                }
                if ui.button("Cancel").clicked() {
                    saving.cancel.store(true, Ordering::Relaxed);
                }
            });
        }
        if let Some(verified) = self.verified.get(id) {
            match verified {
                Verified::Matches(sum) => {
                    ui.colored_label(theme::good(), format!("Verified: matches {sum}"));
                }
                Verified::Differs { computed, recorded } => {
                    crate::activity::error_toast(
                        ui,
                        format!(
                            "The image does not match its recorded SHA-256.\nrecorded {recorded}\ncomputed {computed}"
                        ),
                    );
                }
                Verified::Computed(sum) => {
                    ui.colored_label(
                        theme::muted(),
                        format!("No SHA-256 was recorded; the image hashes to {sum}"),
                    );
                }
                Verified::Failed(error) => {
                    crate::activity::error_toast(ui, error);
                }
            }
        }
    }

    /// Open the Import image… dialog.
    pub(super) fn open_import(&mut self) {
        if self.import.is_none() {
            self.import = Some(Import {
                path: String::new(),
                picker: None,
                error: None,
            });
        }
    }

    /// Finish the file chooser of the import dialog when it closed.
    fn poll_picker(&mut self) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let Some(child) = import.picker.as_mut() else {
            return;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return;
        };
        let mut child = import.picker.take().expect("picker is running");
        let mut text = String::new();
        if let (true, Some(stdout)) = (status.success(), child.stdout.take()) {
            use std::io::Read;
            let _ = stdout.take(8192).read_to_string(&mut text);
        }
        let _ = child.wait();
        let path = text.trim_end_matches('\n');
        if !path.is_empty() {
            import.path = path.to_owned();
        }
    }

    /// The Import image… window. A raw ext4 image stays where it is; a qcow2
    /// image is converted into a dump by `qemu-img` inside the sandbox.
    pub(super) fn import_window(&mut self, ctx: &egui::Context, cx: &DiskContext<'_>) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let mut open = true;
        let mut close = false;
        let mut done = None;
        let mut queued = None;
        crate::widgets::window("Import disk image")
            .id(egui::Id::new("disk_import"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .show(ctx, |ui| {
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(
                            "A raw ext4 image of one filesystem (the whole disk of a VM, as \
                             `mkfs.ext4` or a dump makes it): the file stays where it is and its \
                             content is only read in the isolated reader. Or a qcow2 image: it is \
                             converted into a new dump by qemu-img inside the sandbox, and \
                             refused if it depends on a backing file.",
                        )
                        .color(theme::muted()),
                    )
                    .wrap(),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Image file");
                    ui.add(
                        egui::TextEdit::singleline(&mut import.path)
                            .hint_text(theme::hint_text("/path/to/root.ext4"))
                            .font(egui::TextStyle::Monospace)
                            .margin(theme::TEXT_EDIT_MARGIN)
                            .desired_width(320.0),
                    );
                    if ui
                        .add_enabled(import.picker.is_none(), egui::Button::new("Browse…"))
                        .on_disabled_hover_text("The file chooser is open")
                        .clicked()
                    {
                        match std::process::Command::new("zenity")
                            .args([
                                "--file-selection",
                                "--title=Choose a raw ext4 or qcow2 image",
                            ])
                            .stdout(Stdio::piped())
                            .stderr(Stdio::null())
                            .spawn()
                        {
                            Ok(child) => import.picker = Some(child),
                            Err(error) => {
                                import.error = Some(format!("File chooser (zenity): {error}"));
                            }
                        }
                    }
                });
                if let Some(error) = &import.error {
                    crate::activity::error(ui, error);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let ready = !import.path.trim().is_empty();
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(
                                egui::RichText::new("Import").color(theme::palette().primary_text),
                            )
                            .fill(theme::primary()),
                        )
                        .clicked()
                    {
                        let path = crate::folders::user_path(&import.path);
                        match (cx.recordings, cx.vm) {
                            (Some(recordings), Some(vm)) => {
                                if is_qcow2(&path) {
                                    queued = Some(path);
                                } else {
                                    match dump::import(recordings, &vm.id, &vm.name, &path) {
                                        Ok(imported) => done = Some(imported.id),
                                        Err(error) => import.error = Some(error),
                                    }
                                }
                            }
                            _ => import.error = Some("Select a VM first".into()),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if let Some(path) = queued {
            if cx.job.is_some() || cx.other_job {
                if let Some(import) = self.import.as_mut() {
                    import.error =
                        Some("Another disk job is running: wait for it or cancel it".into());
                }
            } else {
                self.wait_for(false);
                self.action = Some(DiskAction::ImportQcow2(path));
                close = true;
            }
        }
        if done.is_some()
            || close
            || !open
            || ctx.input(|input| input.key_pressed(egui::Key::Escape))
        {
            ctx.request_repaint();
            if let Some(mut child) = self.import.take().and_then(|import| import.picker) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(id) = done {
            self.scan(cx.recording_roots);
            self.entry = Entry::Dump(id);
        }
    }
}

/// A file name to propose when saving: the VM, the date and the format.
fn suggested_name(dump: &DiskDump, format: ExportFormat) -> String {
    let vm: String = dump
        .vm_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let vm = if vm.is_empty() { "disk".to_owned() } else { vm };
    let date = crate::time_format::local_seconds(dump.started_ms / 1000)
        .split_whitespace()
        .next()
        .unwrap_or("dump")
        .to_owned();
    let extension = match format {
        ExportFormat::SparseRaw => "ext4",
        ExportFormat::Qcow2 => "qcow2",
    };
    format!("{vm}-{date}.{extension}")
}

/// The save chooser: `None` when the user closed it.
fn choose_destination(suggestion: &str) -> Result<Option<PathBuf>, String> {
    let output = std::process::Command::new("zenity")
        .args([
            "--file-selection",
            "--save",
            "--confirm-overwrite",
            "--title=Save the disk image to the host",
        ])
        .arg(format!("--filename={suggestion}"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("File chooser (zenity) unavailable: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let destination = PathBuf::from(text.trim_end_matches('\n'));
    Ok((destination.is_absolute()).then_some(destination))
}

/// Whether the file starts with the qcow2 magic. Read on a click.
fn is_qcow2(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok_and(|()| &head == b"QFI\xfb")
}
