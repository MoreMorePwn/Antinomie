// SPDX-License-Identifier: GPL-3.0-only
//! Add to Samples… for a file a run left in a VM (a lineage node). The dialog
//! lists where the bytes could come from; it reads only bytes that already
//! exist, so a run with no readable disk dump has nothing to offer and the
//! action says why. The new sample records the run, the path, the process
//! that wrote it and the sample it came from.
use super::*;
use antinomie_monitor_core::samples::{promote, Added, Library, NewOrigin, NewSample, OriginKind};
use std::path::{Path, PathBuf};

/// One run the file was seen in.
pub(super) struct RunChoice {
    pub(super) number: usize,
    pub(super) run_id: String,
    pub(super) vm_id: String,
    pub(super) vm_name: String,
    pub(super) directory: PathBuf,
    /// The disk dump the bytes can be read from, when there is one.
    pub(super) dump: Option<String>,
}

enum State {
    Idle,
    Working(Receiver<Result<Added, String>>),
    Done(String),
    Failed(String),
}

/// Reads a file out of a run's saved disk: the run's folder and the guest path.
type Extract = fn(&Path, &str) -> Result<Vec<u8>, String>;

pub(super) struct Promote {
    /// The file in the guest.
    path: String,
    /// The hash the run recorded for it, empty when it has none.
    sha256: String,
    /// The sample whose run it was seen in.
    parent: String,
    /// The image that wrote it, empty when not known.
    writer: String,
    runs: Vec<RunChoice>,
    chosen: usize,
    state: State,
    extract: Extract,
    data_dir: PathBuf,
    pub(super) open: bool,
    /// The library changed: the page reads it again.
    pub(super) added: bool,
}

impl Promote {
    pub(super) fn new(
        data_dir: &Path,
        path: String,
        sha256: String,
        parent: String,
        writer: String,
        mut runs: Vec<RunChoice>,
    ) -> Self {
        for run in &mut runs {
            run.dump = promote::dump_label(&run.directory);
        }
        // The newest run with a dump first.
        let chosen = runs.iter().position(|run| run.dump.is_some()).unwrap_or(0);
        Self {
            path,
            sha256,
            parent,
            writer,
            runs,
            chosen,
            state: State::Idle,
            extract: promote::extract_from_dump,
            data_dir: data_dir.to_path_buf(),
            open: true,
            added: false,
        }
    }

    #[cfg(test)]
    pub(super) fn with_extractor(mut self, extract: Extract) -> Self {
        self.extract = extract;
        self
    }

    /// Whether any run has bytes to offer.
    pub(super) fn available(&self) -> bool {
        self.runs.iter().any(|run| run.dump.is_some())
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(run) = self.runs.get(self.chosen) else {
            return;
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        let (extract, data_dir) = (self.extract, self.data_dir.clone());
        let (path, expected, parent, writer) = (
            self.path.clone(),
            self.sha256.clone(),
            self.parent.clone(),
            self.writer.clone(),
        );
        let (directory, run_id, vm_id, vm_name, number) = (
            run.directory.clone(),
            run.run_id.clone(),
            run.vm_id.clone(),
            run.vm_name.clone(),
            run.number,
        );
        let wake = ctx.clone();
        let started = std::thread::Builder::new()
            .name("sample-promote".into())
            .spawn(move || {
                let result = (|| {
                    let bytes = extract(&directory, &path)?;
                    if !expected.is_empty() {
                        let actual = antinomie_monitor_core::storage::sha256_hex(&bytes);
                        if actual != expected {
                            return Err(format!(
                                "the file in the disk dump has SHA-256 {} and the run recorded {}: it changed after the run, so it is not added",
                                &actual[..16],
                                &expected[..16.min(expected.len())]
                            ));
                        }
                    }
                    let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
                    Library::open(&data_dir)?.add_bytes(
                        &bytes,
                        NewSample {
                            name: name.clone(),
                            origin: NewOrigin {
                                kind: OriginKind::Promoted,
                                source: format!("Run {number}, disk dump"),
                                detail: if writer.is_empty() {
                                    String::new()
                                } else {
                                    format!("written by {writer}")
                                },
                                name,
                                path,
                                vm_id,
                                vm_name,
                                run_id,
                                parent,
                            },
                            ..NewSample::default()
                        },
                    )
                })();
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.state = match started {
            Ok(_) => State::Working(receiver),
            Err(error) => State::Failed(error.to_string()),
        };
    }

    fn poll(&mut self) {
        let State::Working(receiver) = &self.state else {
            return;
        };
        if let Ok(result) = receiver.try_recv() {
            self.state = match result {
                Ok(added) => {
                    self.added = true;
                    State::Done(if added.new {
                        "Added to Samples".into()
                    } else {
                        "Already in Samples: origin added".into()
                    })
                }
                Err(error) => State::Failed(error),
            };
        }
    }

    /// Draw the window.
    pub(super) fn show(&mut self, ctx: &egui::Context) {
        self.poll();
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
        }
        let mut open = self.open;
        let mut start = false;
        egui::Window::new("Add to Samples")
            .id(egui::Id::new("sample_promote"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("File").color(theme::muted()));
                    ui.label(RichText::new(&self.path).monospace());
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("SHA-256").color(theme::muted()));
                    if self.sha256.is_empty() {
                        ui.label(theme::hint_text("unknown"));
                    } else {
                        ui.label(RichText::new(&self.sha256).monospace().small());
                    }
                });
                ui.add_space(6.0);
                ui.label(RichText::new("Bytes from").strong());
                let idle = matches!(self.state, State::Idle);
                for (index, run) in self.runs.iter().enumerate() {
                    let text = match &run.dump {
                        Some(label) => format!("Run {} · disk dump {label}", run.number),
                        None => format!("Run {} · no disk dump saved", run.number),
                    };
                    ui.add_enabled_ui(run.dump.is_some() && idle, |ui| {
                        ui.radio_value(&mut self.chosen, index, text);
                    });
                }
                for (name, why) in [
                    ("The guest", "Reading a file out of a VM is not offered here"),
                    ("A rule-saved copy", "No rule saved a copy of this file"),
                ] {
                    ui.add_enabled(false, egui::RadioButton::new(false, name))
                        .on_disabled_hover_text(why);
                }
                ui.add_space(6.0);
                match &self.state {
                    State::Working(_) => {
                        ui.horizontal(|ui| {
                            theme::spinner(ui);
                            ui.label("Reading the file…");
                        });
                    }
                    State::Done(message) => {
                        ui.colored_label(theme::good(), message);
                    }
                    State::Failed(error) => {
                        ui.colored_label(theme::error(), error);
                    }
                    State::Idle if !self.available() => {
                        ui.label(theme::hint_text(
                            "No bytes exist for this file: none of its runs has a readable disk dump.",
                        ));
                    }
                    State::Idle => {}
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            idle && self.runs.get(self.chosen).is_some_and(|r| r.dump.is_some()),
                            egui::Button::new("Add to Samples"),
                        )
                        .clicked()
                    {
                        start = true;
                    }
                    if ui.button("Close").clicked() {
                        self.open = false;
                    }
                });
            });
        if start {
            self.start(ctx);
        }
        self.open = open && self.open;
    }

    #[cfg(test)]
    pub(super) fn finished(&self) -> Option<Result<String, String>> {
        match &self.state {
            State::Done(message) => Some(Ok(message.clone())),
            State::Failed(error) => Some(Err(error.clone())),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn run_for_test(&mut self, ctx: &egui::Context) {
        if let Some(run) = self.runs.get_mut(self.chosen) {
            run.dump = Some("test dump".into());
        }
        self.start(ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::{Library, NewSample};

    fn data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ant-ui-promote-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dropped(_: &Path, _: &str) -> Result<Vec<u8>, String> {
        Ok(b"\x7fELF dropped payload".to_vec())
    }

    fn promote_in(dir: &Path, parent: &str, sha256: &str) -> Promote {
        Promote::new(
            dir,
            "/tmp/.x".into(),
            sha256.into(),
            parent.into(),
            "/tmp/install.sh".into(),
            vec![RunChoice {
                number: 2,
                run_id: "r2".into(),
                vm_id: "vm".into(),
                vm_name: "Debian".into(),
                directory: dir.join("run"),
                dump: None,
            }],
        )
        .with_extractor(dropped)
    }

    fn wait(promote: &mut Promote) -> Result<String, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            promote.poll();
            if let Some(result) = promote.finished() {
                return result;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "promotion did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn a_run_without_a_dump_has_nothing_to_offer() {
        let dir = data_dir("none");
        let promote = promote_in(&dir, "ab", "");
        assert!(!promote.available());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn promoting_adds_the_bytes_with_run_path_writer_and_parent() {
        let dir = data_dir("add");
        let parent = Library::open(&dir)
            .unwrap()
            .add_bytes(
                b"#!/bin/sh\n",
                NewSample {
                    name: "install.sh".into(),
                    ..NewSample::default()
                },
            )
            .unwrap()
            .sha256;
        let ctx = egui::Context::default();
        let mut promote = promote_in(&dir, &parent, "");
        promote.run_for_test(&ctx);
        assert_eq!(wait(&mut promote), Ok("Added to Samples".into()));
        assert!(promote.added);
        let library = Library::open(&dir).unwrap();
        let child = library
            .list()
            .unwrap()
            .into_iter()
            .find(|record| record.name == ".x")
            .expect("the promoted file");
        let origin = &library.origins(&child.sha256).unwrap()[0];
        assert_eq!(origin.kind, OriginKind::Promoted);
        assert_eq!(
            (origin.parent.as_str(), origin.run_id.as_str()),
            (parent.as_str(), "r2")
        );
        assert_eq!(origin.path, "/tmp/.x");
        assert!(origin.detail.contains("/tmp/install.sh"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_that_changed_since_the_run_is_refused() {
        let dir = data_dir("changed");
        let ctx = egui::Context::default();
        let mut promote = promote_in(&dir, "ab", &"0".repeat(64));
        promote.run_for_test(&ctx);
        let error = wait(&mut promote).unwrap_err();
        assert!(error.contains("changed after the run"), "{error}");
        assert!(!promote.added);
        let _ = std::fs::remove_dir_all(dir);
    }
}
