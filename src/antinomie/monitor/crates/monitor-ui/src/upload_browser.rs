// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Lazy, bounded host directory browsing off the native rendering thread.
use crate::theme;
use eframe::egui;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

const PAGE_LEN: usize = 256;
const DIRECTORY_LIMIT: usize = 32;
const DEPTH_LIMIT: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Select(PathBuf),
    SendRun(PathBuf),
    OpenDirectory(PathBuf),
}

#[derive(Clone, Copy)]
struct View {
    id: &'static str,
    height: f32,
    actions: bool,
    can_send: bool,
}

#[derive(Clone, Debug)]
struct Entry {
    path: PathBuf,
    directory: bool,
    regular: bool,
}

#[derive(Debug)]
struct Page {
    entries: Vec<Entry>,
    more: bool,
}

struct Listing {
    offset: usize,
    result: Option<Result<Page, String>>,
}

struct Request {
    generation: u64,
    path: PathBuf,
    offset: usize,
    cancel: Arc<AtomicBool>,
}

struct Answer {
    generation: u64,
    path: PathBuf,
    offset: usize,
    result: Result<Page, String>,
}

struct Worker {
    sender: Option<mpsc::SyncSender<Request>>,
    receiver: Option<mpsc::Receiver<Answer>>,
    thread: Option<thread::JoinHandle<()>>,
    pending: Option<Arc<AtomicBool>>,
}

impl Worker {
    fn new() -> Result<Self, String> {
        let (sender, requests) = mpsc::sync_channel::<Request>(1);
        let (answers, receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("upload-browser".into())
            .spawn(move || {
                while let Ok(request) = requests.recv() {
                    let result = read_page(&request.path, request.offset, &request.cancel);
                    if answers
                        .send(Answer {
                            generation: request.generation,
                            path: request.path,
                            offset: request.offset,
                            result,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|error| format!("Host browser: {error}"))?;
        Ok(Self {
            sender: Some(sender),
            receiver: Some(receiver),
            thread: Some(thread),
            pending: None,
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(cancel) = &self.pending {
            cancel.store(true, Ordering::Relaxed);
        }
        self.sender.take();
        self.receiver.take();
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                eprintln!("upload browser worker panicked");
            }
        }
    }
}

fn read_page(path: &Path, offset: usize, cancel: &AtomicBool) -> Result<Page, String> {
    let directory = std::fs::read_dir(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
    let mut entries = Vec::with_capacity(PAGE_LEN);
    let mut more = false;
    for (index, entry) in directory.enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("Folder reading cancelled".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        if index < offset {
            continue;
        }
        if entries.len() == PAGE_LEN {
            more = true;
            break;
        }
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        entries.push(Entry {
            path: entry.path(),
            directory: kind.is_dir(),
            regular: kind.is_file(),
        });
    }
    entries.sort_by(|a, b| {
        b.directory
            .cmp(&a.directory)
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(Page { entries, more })
}

#[derive(Default)]
pub(crate) struct Browser {
    pub(crate) root: Option<PathBuf>,
    pub(crate) selected: Option<PathBuf>,
    pub(crate) generation: u64,
    listings: BTreeMap<PathBuf, Listing>,
    worker: Option<Worker>,
    error: Option<String>,
}

impl Browser {
    pub(crate) fn reset(&mut self, root: PathBuf) {
        self.invalidate();
        self.root = Some(root);
        self.selected = None;
    }

    pub(crate) fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.listings.clear();
        self.error = None;
        if let Some(cancel) = self
            .worker
            .as_ref()
            .and_then(|worker| worker.pending.as_ref())
        {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    fn poll(&mut self) {
        let answer = self.worker.as_ref().and_then(|worker| {
            worker
                .receiver
                .as_ref()
                .and_then(|receiver| receiver.try_recv().ok())
        });
        if let Some(answer) = answer {
            self.accept(answer);
        }
    }

    fn accept(&mut self, answer: Answer) {
        if let Some(worker) = &mut self.worker {
            worker.pending = None;
        }
        if answer.generation == self.generation {
            if let Some(listing) = self.listings.get_mut(&answer.path) {
                if listing.offset == answer.offset {
                    listing.result = Some(answer.result);
                }
            }
        }
    }

    fn request(&mut self, path: &Path) {
        if self.worker.is_none() {
            match Worker::new() {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => {
                    self.error = Some(error);
                    return;
                }
            }
        }
        let Some(worker) = &mut self.worker else {
            return;
        };
        if worker.pending.is_some() {
            return;
        }
        if !self.listings.contains_key(path) && self.listings.len() >= DIRECTORY_LIMIT {
            self.error = Some("Close an expanded folder or refresh to browse more folders".into());
            return;
        }
        let listing = self.listings.entry(path.to_owned()).or_insert(Listing {
            offset: 0,
            result: None,
        });
        if listing.result.is_some() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let request = Request {
            generation: self.generation,
            path: path.to_owned(),
            offset: listing.offset,
            cancel: Arc::clone(&cancel),
        };
        if let Some(sender) = &worker.sender {
            match sender.try_send(request) {
                Ok(()) => worker.pending = Some(cancel),
                Err(error) => self.error = Some(format!("Host browser: {error}")),
            }
        }
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui) -> Option<PathBuf> {
        match self.show_view(
            ui,
            View {
                id: "upload_host_tree",
                height: 240.0,
                actions: false,
                can_send: false,
            },
        ) {
            Some(Action::Select(path)) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn show_explorer(
        &mut self,
        ui: &mut egui::Ui,
        height: f32,
        can_send: bool,
    ) -> Option<Action> {
        self.show_view(
            ui,
            View {
                id: "sidebar_host_tree",
                height,
                actions: true,
                can_send,
            },
        )
    }

    fn show_view(&mut self, ui: &mut egui::Ui, view: View) -> Option<Action> {
        self.poll();
        let Some(root) = self.root.clone() else {
            ui.colored_label(theme::muted(), "Choose a host folder to browse its files.");
            return None;
        };
        if let Some(error) = &self.error {
            ui.colored_label(theme::error(), error);
        }
        let mut selected = None;
        egui::ScrollArea::both()
            .id_salt(view.id)
            .max_height(view.height.max(24.0))
            .min_scrolled_height(view.height.clamp(24.0, 100.0))
            .show(ui, |ui| self.directory(ui, &root, 0, view, &mut selected));
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.pending.is_some())
        {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(50));
        }
        if let Some(Action::Select(path) | Action::SendRun(path)) = &selected {
            self.selected = Some(path.clone());
        }
        selected
    }

    fn directory(
        &mut self,
        ui: &mut egui::Ui,
        path: &Path,
        depth: usize,
        view: View,
        selected: &mut Option<Action>,
    ) {
        if depth >= DEPTH_LIMIT {
            ui.colored_label(
                theme::muted(),
                "Choose this folder as the root to browse deeper.",
            );
            return;
        }
        self.request(path);
        let Some(listing) = self.listings.get(path) else {
            return;
        };
        let Some(result) = &listing.result else {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading folder…");
            });
            return;
        };
        let page = match result {
            Ok(page) => page,
            Err(error) => {
                ui.colored_label(theme::error(), error);
                return;
            }
        };
        let entries = page.entries.clone();
        let entry_count = entries.len();
        let more = page.more;
        let offset = listing.offset;
        if entries.is_empty() {
            ui.colored_label(theme::muted(), "No entries in this folder.");
        }
        for entry in entries {
            let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
            if entry.directory {
                let response = egui::CollapsingHeader::new(name.as_ref())
                    .id_salt((view.id, &entry.path, self.generation))
                    .show(ui, |ui| {
                        self.directory(ui, &entry.path, depth + 1, view, selected)
                    });
                if view.actions {
                    response.header_response.context_menu(|ui| {
                        if ui.button("Open Directory").clicked() {
                            *selected = Some(Action::OpenDirectory(entry.path.clone()));
                            ui.close_menu();
                        }
                    });
                }
                if response.body_returned.is_none() {
                    self.listings
                        .retain(|path, _| !path.starts_with(&entry.path));
                }
            } else {
                let available = entry.regular && entry.path.to_str().is_some();
                let response = ui
                    .add_enabled(
                        available,
                        egui::SelectableLabel::new(
                            self.selected.as_ref() == Some(&entry.path), name.as_ref()),
                    )
                    .on_hover_text(if available {
                        if view.actions {
                            format!("{}\n{}", entry.path.display(), if view.can_send {
                                "Double-click to Send and Run; right-click for actions"
                            } else {
                                "Start the selected VM and wait for any pending upload to Send and Run"
                            })
                        } else { entry.path.display().to_string() }
                    } else {
                        "Only regular files with UTF-8 paths can be selected; links and special files are not followed".into()
                    });
                if response.clicked() || response.secondary_clicked() {
                    *selected = Some(Action::Select(entry.path.clone()));
                }
                if view.actions && available {
                    if response.double_clicked() && view.can_send {
                        *selected = Some(Action::SendRun(entry.path.clone()));
                    }
                    response.context_menu(|ui| {
                        if ui
                            .add_enabled(view.can_send, egui::Button::new("Send and Run"))
                            .clicked()
                        {
                            *selected = Some(Action::SendRun(entry.path.clone()));
                            ui.close_menu();
                        }
                        if ui.button("Open Directory").clicked() {
                            if let Some(parent) = entry.path.parent() {
                                *selected = Some(Action::OpenDirectory(parent.to_owned()));
                            }
                            ui.close_menu();
                        }
                    });
                }
            }
        }
        if offset > 0 || more {
            let mut next = None;
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Entries {}–{}", offset + 1, offset + entry_count));
                if ui
                    .add_enabled(offset > 0, egui::Button::new("Previous entries"))
                    .clicked()
                {
                    next = Some(offset.saturating_sub(PAGE_LEN));
                }
                if ui
                    .add_enabled(more, egui::Button::new("Next entries"))
                    .clicked()
                {
                    next = offset.checked_add(PAGE_LEN);
                }
            });
            if let Some(offset) = next {
                self.listings
                    .retain(|key, _| key == path || !key.starts_with(path));
                self.listings.insert(
                    path.to_owned(),
                    Listing {
                        offset,
                        result: None,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    pub(crate) struct Fixture(pub(crate) PathBuf);

    impl Fixture {
        pub(crate) fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "antinomie-upload-browser-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn directory_pages_cover_large_folders_and_distinguish_files_links_and_pipes() {
        let fixture = Fixture::new();
        for index in 0..(PAGE_LEN + 17) {
            std::fs::write(fixture.0.join(format!("file-{index}")), b"test").unwrap();
        }
        let sub = fixture.0.join("subfolder");
        std::fs::create_dir(&sub).unwrap();
        std::os::unix::fs::symlink(&fixture.0, fixture.0.join("cycle")).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(fixture.0.join("pipe"))
            .status()
            .unwrap()
            .success());
        let cancel = AtomicBool::new(false);
        let first = read_page(&fixture.0, 0, &cancel).unwrap();
        let second = read_page(&fixture.0, PAGE_LEN, &cancel).unwrap();
        assert_eq!(first.entries.len(), PAGE_LEN);
        assert!(first.more && !second.more);
        let all: BTreeMap<_, _> = first
            .entries
            .into_iter()
            .chain(second.entries)
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        assert_eq!(all.len(), PAGE_LEN + 20);
        assert!(all[&sub].directory);
        assert!(!all[&fixture.0.join("cycle")].directory);
        assert!(!all[&fixture.0.join("cycle")].regular);
        assert!(!all[&fixture.0.join("pipe")].regular);
    }

    #[test]
    fn unreadable_removed_and_cancelled_folders_report_errors() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file"), b"test").unwrap();
        assert!(read_page(&fixture.0.join("removed"), 0, &AtomicBool::new(false)).is_err());
        assert!(read_page(&fixture.0.join("file"), 0, &AtomicBool::new(false)).is_err());
        assert!(read_page(&fixture.0, 0, &AtomicBool::new(true))
            .unwrap_err()
            .contains("cancelled"));
    }

    #[test]
    fn explorer_open_directory_action_returns_containing_folder_without_uploading() {
        let fixture = Fixture::new();
        let file = fixture.0.join("directory-action.txt");
        std::fs::write(&file, b"test").unwrap();
        let mut browser = Browser::default();
        browser.reset(fixture.0.clone());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut time = 0.0;
        let mut render = |events| {
            time += 0.016;
            let mut action = None;
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(600.0, 400.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        action = browser.show_explorer(ui, 300.0, true);
                    });
                },
            );
            (action, super::super::tests::texts(&output))
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let position = loop {
            let (_, texts) = render(vec![]);
            if let Some((_, rect)) = texts
                .iter()
                .find(|(text, _)| text == "directory-action.txt")
            {
                break rect.center();
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        for pressed in [true, false] {
            render(vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Secondary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
        let mut shown = Vec::new();
        for _ in 0..3 {
            shown = render(vec![]).1;
        }
        let position = shown
            .iter()
            .find(|(text, _)| text == "Open Directory")
            .unwrap()
            .1
            .center();
        let mut action = None;
        for pressed in [true, false] {
            action = render(vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ])
            .0;
        }
        assert_eq!(action, Some(Action::OpenDirectory(fixture.0.clone())));
    }

    #[test]
    fn worker_result_from_old_root_is_ignored_then_new_root_loads() {
        let first = Fixture::new();
        let second = Fixture::new();
        std::fs::write(first.0.join("old-file"), b"old").unwrap();
        std::fs::write(second.0.join("new-file"), b"new").unwrap();
        let mut browser = Browser::default();
        browser.reset(first.0.clone());
        browser.request(&first.0);
        browser.reset(second.0.clone());
        let answer = browser
            .worker
            .as_ref()
            .unwrap()
            .receiver
            .as_ref()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        browser.accept(answer);
        assert!(browser.listings.is_empty());
        browser.request(&second.0);
        let answer = browser
            .worker
            .as_ref()
            .unwrap()
            .receiver
            .as_ref()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        browser.accept(answer);
        let page = browser.listings[&second.0]
            .result
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap();
        assert_eq!(page.entries[0].path, second.0.join("new-file"));
    }
}
