// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Lazy, bounded host directory browsing off the native rendering thread.
use crate::theme;
mod rows;
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

/// Entries of one page, expanded folders kept and tree depth shown: shared by
/// every lazy tree in the app (the Disks tab uses them too).
pub(crate) const PAGE_LEN: usize = 256;
pub(crate) const DIRECTORY_LIMIT: usize = 32;
pub(crate) const DEPTH_LIMIT: usize = 16;

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
    wake: egui::Context,
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
                    let wake = request.wake.clone();
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
                    wake.request_repaint_of(egui::ViewportId::ROOT);
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
    expanded: std::collections::BTreeSet<PathBuf>,
    rows: Vec<rows::Row>,
    /// The tree branches in front of each of `rows`.
    branches: Vec<crate::tree_lines::Prefix>,
    rows_dirty: bool,
    #[cfg(test)]
    drawn_rows: usize,
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
        self.expanded.clear();
        self.rows.clear();
        self.rows_dirty = true;
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
                    self.rows_dirty = true;
                }
            }
        }
    }

    fn request(&mut self, path: &Path, ctx: &egui::Context) {
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
            wake: ctx.clone(),
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
        rows::show(self, ui, view)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn expanded_tree_only_builds_viewport_widgets_and_reuses_cached_rows() {
        let fixture = Fixture::new();
        let mut browser = Browser::default();
        browser.reset(fixture.0.clone());
        let mut directories = Vec::new();
        for folder in 0..16 {
            let path = fixture.0.join(format!("folder-{folder:02}"));
            directories.push(Entry {
                path: path.clone(),
                directory: true,
                regular: false,
            });
            browser.expanded.insert(path.clone());
            let entries = (0..PAGE_LEN)
                .map(|index| Entry {
                    path: path.join(format!("file-{folder:02}-{index:03}")),
                    directory: false,
                    regular: true,
                })
                .collect();
            browser.listings.insert(
                path,
                Listing {
                    offset: 0,
                    result: Some(Ok(Page {
                        entries,
                        more: false,
                    })),
                },
            );
        }
        browser.listings.insert(
            fixture.0.clone(),
            Listing {
                offset: 0,
                result: Some(Ok(Page {
                    entries: directories,
                    more: false,
                })),
            },
        );
        let ctx = egui::Context::default();
        theme::install(&ctx);
        for pass in 0..4 {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(600.0, 400.0),
                    )),
                    time: Some(pass as f64 * 0.1),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        browser.show_explorer(ui, 200.0, true);
                    });
                },
            );
            assert_eq!(browser.rows.len(), 16 * (PAGE_LEN + 1));
            assert!(
                browser.drawn_rows < 30,
                "only visible rows render, not all {}",
                browser.rows.len()
            );
            assert!(!browser.rows_dirty);
        }
        let allocation = browser.rows.as_ptr();
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                browser.show_explorer(ui, 200.0, true);
            });
        });
        assert_eq!(
            allocation,
            browser.rows.as_ptr(),
            "unchanged frames reuse the flattened tree"
        );
    }

    #[test]
    fn expanded_folders_get_tree_branches_for_their_entries_and_paging_row() {
        let root = PathBuf::from("/root");
        let entry = |name: &str, directory: bool| Entry {
            path: root.join(name),
            directory,
            regular: !directory,
        };
        let listing = |entries: Vec<Entry>, more| Listing {
            offset: 0,
            result: Some(Ok(Page { entries, more })),
        };
        let mut browser = Browser::default();
        browser.reset(root.clone());
        browser.listings.insert(
            root.clone(),
            listing(vec![entry("a", true), entry("b", false)], false),
        );
        browser.listings.insert(
            root.join("a"),
            listing(vec![entry("a/x", false), entry("a/y", false)], true),
        );
        browser.expanded.insert(root.join("a"));
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let view = View {
                    id: "branches",
                    height: 200.0,
                    actions: false,
                    can_send: false,
                };
                rows::show(&mut browser, ui, view);
            });
        });
        // ├── a
        // │   ├── x
        // │   ├── y
        // │   └── the paging row
        // └── b
        let shown: Vec<_> = browser
            .branches
            .iter()
            .map(|branch| branch.text())
            .collect();
        assert_eq!(shown, ["├── ", "│   ├── ", "│   ├── ", "│   └── ", "└── "]);
        assert_eq!(browser.rows.len(), browser.branches.len());
    }

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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
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
    fn short_explorer_contents_fill_available_width_at_normal_and_large_fonts() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("a"), b"test").unwrap();
        for font in [16.0, 24.0] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font);
            let mut browser = Browser::default();
            browser.reset(fixture.0.clone());
            browser.listings.insert(
                fixture.0.clone(),
                Listing {
                    offset: 0,
                    result: Some(read_page(&fixture.0, 0, &AtomicBool::new(false))),
                },
            );
            let _ = ctx.run(egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(600.0, 400.0))),
                ..Default::default()
            }, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let expected = ui.available_rect_before_wrap().right();
                    let area = ui.scope(|ui| { browser.show_explorer(ui, 250.0, true); });
                    assert!((area.response.rect.right() - expected).abs() < 1.0,
                        "Explorer must fill the pane, even with one short filename: {:?} vs {expected}", area.response.rect);
                });
            });
        }
    }

    #[test]
    fn worker_result_from_old_root_is_ignored_then_new_root_loads() {
        let first = Fixture::new();
        let second = Fixture::new();
        std::fs::write(first.0.join("old-file"), b"old").unwrap();
        std::fs::write(second.0.join("new-file"), b"new").unwrap();
        let mut browser = Browser::default();
        browser.reset(first.0.clone());
        browser.request(&first.0, &egui::Context::default());
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
        browser.request(&second.0, &egui::Context::default());
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
