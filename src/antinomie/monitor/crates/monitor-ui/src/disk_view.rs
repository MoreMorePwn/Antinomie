// SPDX-License-Identifier: MIT
//! The Disks tab: a read-only view of a VM's current disk while the VM is
//! off. The backend flattens the disk chain into a scratch image (`Open`);
//! a sandboxed reader (two of them: one browses, one finds and extracts)
//! serves the filesystem tree, Details and extraction. Nothing from the
//! guest is ever executed on the host.
//!
//! The entries are "Current disk (VM off)" and the saved disk dumps (made from
//! it, or imported) newest first. A dump is a plain file: it stays browsable
//! while the VM runs. Checkpoint sources (phase 3) add entry kinds beside
//! `Current`.
use antinomie_monitor_core::{
    disks::{
        dump::DiskDump,
        reader::{DiskEntryKind, DiskFileInfo, DiskImageInfo, DiskRequest, FindResults},
        CurrentDiskView, DiskJobProgress, DiskMeasure,
    },
    VmConfig,
};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

mod details;
mod dump_actions;
mod dumps;
mod entries;
mod extraction;
mod find;
mod main_pane;
mod tree;
mod worker;

pub(crate) use antinomie_monitor_core::disks::format_size;

/// Largest file Extract to view loads into the viewer.
const VIEW_CAP: u64 = crate::data_view::DATA_WINDOW_CAP;

/// Persisted settings of the tab (serde-default, so older files load).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DiskSettings {
    /// Largest file extracted without asking, in MiB.
    pub extract_cap_mib: u32,
    /// Largest file hashed on demand, in MiB.
    pub hash_cap_mib: u32,
    pub hide_dotfiles: bool,
    /// Show modes as octal numbers instead of `rwx`.
    pub numeric_modes: bool,
    /// Compute the SHA-256 of a disk dump (views are never hashed).
    pub dump_hash: bool,
    /// Also record the SHA-256 of every layer of the chain a dump was read
    /// from: doubles the time of a dump, for evidence-grade provenance.
    pub source_digests: bool,
}

impl Default for DiskSettings {
    fn default() -> Self {
        Self {
            extract_cap_mib: 256,
            hash_cap_mib: 64,
            hide_dotfiles: false,
            numeric_modes: false,
            dump_hash: true,
            source_digests: false,
        }
    }
}

impl DiskSettings {
    pub(crate) fn extract_cap(&self) -> u64 {
        u64::from(self.extract_cap_mib) * 1024 * 1024
    }

    pub(crate) fn hash_cap(&self) -> u64 {
        u64::from(self.hash_cap_mib) * 1024 * 1024
    }
}

/// What the tab asks the application to do.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DiskAction {
    Measure,
    Open,
    Close,
    /// Dump the VM's current disk.
    Dump,
    /// Promote the open view to a dump.
    Keep,
    Cancel,
    /// Ask to delete a saved dump (the app confirms, the backend deletes).
    Delete(Box<DiskDump>),
    /// The running-state notice's shortcut: the toolbar's Stop.
    StopVm,
    /// Show an extracted file in the data viewer.
    ViewBytes {
        key: String,
        title: String,
        bytes: Vec<u8>,
    },
    /// Run static analysis on an extracted host file.
    Analyze(PathBuf),
    /// Hand an extracted host file to the desktop's application.
    OpenWith(PathBuf),
}

pub(crate) struct DiskContext<'a> {
    pub vm: Option<&'a VmConfig>,
    /// Where this VM's dumps and imports go.
    pub recordings: Option<&'a Path>,
    /// Every recording directory of the VM, to list dumps from.
    pub recording_roots: &'a [PathBuf],
    /// `qemu-img`, for saving a dump's image to the host.
    pub qemu_img: &'a Path,
    /// The selected VM is not the one that runs.
    pub vm_off: bool,
    pub can_stop_vm: bool,
    /// Filtered to the selected VM.
    pub current_disk: Option<&'a CurrentDiskView>,
    pub measure: Option<&'a DiskMeasure>,
    pub job: Option<&'a DiskJobProgress>,
    /// A disk job of another VM holds the single job slot.
    pub other_job: bool,
    pub font_size: f32,
    pub settings: &'a mut DiskSettings,
}

/// Which entry of the list is selected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Entry {
    /// "Current disk (VM off)".
    #[default]
    Current,
    /// A saved dump, by id.
    Dump(String),
}

/// What the readers are bound to: the open view, or a saved dump.
struct Bound {
    /// Names the entry; the readers restart when it changes.
    key: String,
    image: PathBuf,
    extract_dir: PathBuf,
    what: What,
}

enum What {
    Current(Box<CurrentDiskView>),
    Dump,
}

/// What a reader request was for.
#[derive(Clone, Debug)]
enum Purpose {
    Probe,
    List {
        path: String,
        offset: usize,
    },
    Info {
        path: String,
    },
    Find,
    Extract {
        path: String,
        intent: extraction::Intent,
    },
}

/// One file extracted in this session.
#[derive(Clone, Debug)]
pub(crate) struct Extracted {
    pub guest_path: String,
    pub host_path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

/// Details of the selected entry.
pub(crate) struct Selection {
    pub path: String,
    pub info: Option<Result<DiskFileInfo, String>>,
    /// Hashes were asked for.
    pub hashed: bool,
}

#[derive(Default)]
pub(crate) struct DiskView {
    /// The selected entry.
    entry: Entry,
    /// The open view or the dump the readers are bound to.
    bound: Option<Bound>,
    /// The saved dumps of the selected VM, newest first, as of the last scan.
    dumps: Vec<dumps::Row>,
    dumps_for: Option<Vec<PathBuf>>,
    /// What the last scan was taken for, to scan again when it changes.
    scan_key: dumps::ScanKey,
    import: Option<dump_actions::Import>,
    verify: Option<dump_actions::Verify>,
    verified: BTreeMap<String, dump_actions::Verified>,
    saving_image: Option<dump_actions::ImageSave>,
    /// The dump the open Current disk view was kept as: it reads its image.
    open_kept: Option<String>,
    /// `qemu-img`, as of the last frame, for the Details dock.
    qemu_img: PathBuf,
    browse: Option<worker::Worker>,
    search: Option<worker::Worker>,
    browse_queue: Vec<(u64, worker::Job)>,
    search_queue: Vec<(u64, worker::Job)>,
    purposes: BTreeMap<u64, Purpose>,
    next_token: u64,
    tree: tree::Tree,
    selection: Option<Selection>,
    probe: Option<Result<DiskImageInfo, String>>,
    find: find::Find,
    extracted: Vec<Extracted>,
    extraction: extraction::State,
    /// One line about the last extraction or save, and whether it failed.
    status: Option<(String, bool)>,
    /// Why the view went away, until the user opens another.
    notice: Option<String>,
    /// A request sent to the backend that has no answer yet.
    waiting: Option<Instant>,
    /// The request waits for a measurement or an open view (not for a dump,
    /// which leaves an open view as it is).
    waiting_for_view: bool,
    /// The state for which a measurement was already asked.
    measured_for: Option<(String, bool)>,
    had_measure: bool,
    last_measured: Option<u64>,
    /// The caps and toggles of the last `show`, for the Details pane.
    settings: DiskSettings,
    /// An action from a pane drawn this frame.
    action: Option<DiskAction>,
}

/// The name the lists show for a dump: its annotation, else its default
/// title. Reads the sidecar: for a click, not a frame.
pub(crate) fn dump_name(dump: &DiskDump) -> String {
    antinomie_monitor_core::annotations::load(&dump.dir)
        .ok()
        .map(|annotation| annotation.name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| dumps::dump_title(dump))
}

/// Escape what could mislead in a guest-controlled name: control characters
/// and the Unicode direction overrides.
pub(crate) fn display_name(name: &str) -> String {
    let mut shown = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '\n' => shown.push_str("\\n"),
            '\r' => shown.push_str("\\r"),
            '\t' => shown.push_str("\\t"),
            c if c.is_control() => shown.push_str(&format!("\\x{:02x}", c as u32)),
            '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}' => shown.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => shown.push(c),
        }
    }
    shown
}

/// `drwxr-xr-x`, with the setuid, setgid and sticky bits.
pub(crate) fn mode_rwx(kind: DiskEntryKind, mode: u32) -> String {
    let mut text = String::with_capacity(10);
    text.push(match kind {
        DiskEntryKind::Dir => 'd',
        DiskEntryKind::File => '-',
        DiskEntryKind::Symlink => 'l',
        DiskEntryKind::CharDev => 'c',
        DiskEntryKind::BlockDev => 'b',
        DiskEntryKind::Fifo => 'p',
        DiskEntryKind::Socket => 's',
    });
    for (shift, special, set, unset) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let bits = (mode >> shift) & 0o7;
        text.push(if bits & 4 != 0 { 'r' } else { '-' });
        text.push(if bits & 2 != 0 { 'w' } else { '-' });
        text.push(match (bits & 1 != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    text
}

/// `0755`, four digits.
pub(crate) fn mode_numeric(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// `14:05:12` in the host zone, from epoch seconds.
pub(crate) fn clock(seconds: u64) -> String {
    crate::time_format::local_seconds(seconds)
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .to_owned()
}

impl DiskView {
    /// Follow the backend: bind the readers to the open view, drop them
    /// when it goes away, answer the reader threads, ask for a measurement
    /// once per VM state.
    fn sync(&mut self, ctx: &egui::Context, cx: &DiskContext<'_>) {
        self.settings = cx.settings.clone();
        if self.tree.hide_dotfiles != cx.settings.hide_dotfiles {
            self.tree.hide_dotfiles = cx.settings.hide_dotfiles;
            self.tree.dirty = true;
        }
        if self.qemu_img != cx.qemu_img {
            self.qemu_img = cx.qemu_img.to_path_buf();
        }
        self.open_kept = cx.current_disk.and_then(|view| view.kept_as.clone());
        self.scan_when_needed(cx);
        if self.want(cx)
            != self
                .bound
                .as_ref()
                .map(|b| (b.key.as_str(), b.image.as_path()))
        {
            let restart = self
                .bound
                .as_ref()
                .is_some_and(|bound| self.want(cx).is_some_and(|(key, _)| key == bound.key));
            if restart {
                // The view was kept: the same bytes at the dump's path.
                self.rebind(ctx, cx);
            } else {
                // Another VM selected is not a closed view.
                let closed = matches!(
                    (&self.bound, &self.entry),
                    (Some(Bound { what: What::Current(view), .. }), Entry::Current)
                        if Some(view.vm_id.as_str()) == cx.vm.map(|vm| vm.id.as_str())
                );
                self.unbind();
                self.notice = None;
                if let Some(bound) = self.make_bound(cx) {
                    self.bind(ctx, bound);
                } else if closed {
                    self.notice = Some(if cx.vm_off {
                        "Current disk view closed.".into()
                    } else {
                        "Current disk view closed: VM started. Saved dumps stay available.".into()
                    });
                }
            }
        }
        if let (
            Some(Bound {
                what: What::Current(old),
                ..
            }),
            Some(view),
        ) = (&mut self.bound, cx.current_disk)
        {
            if **old != *view {
                **old = view.clone();
            }
        }
        if cx.current_disk.is_some() {
            self.notice = None;
        }
        // A running VM changes its disk; a dropped measurement (the chain
        // changed) is asked for again.
        if !cx.vm_off || (self.had_measure && cx.measure.is_none()) {
            self.measured_for = None;
        }
        self.had_measure = cx.measure.is_some();
        // A request is answered by its job, or by its result (a small disk is
        // measured or opened between two snapshots).
        let measured = cx.measure.map(|measure| measure.measured_ms);
        if self
            .waiting
            .is_some_and(|since| since.elapsed() > Duration::from_secs(5))
            || cx.job.is_some()
            || (cx.current_disk.is_some() && self.waiting_for_view)
            || (measured.is_some() && measured != self.last_measured)
        {
            self.waiting = None;
        }
        self.last_measured = measured;
        self.poll_save(ctx);
        self.poll_dump_actions(ctx);
        self.pump(ctx);
    }

    /// The key and image of what the readers should be bound to.
    fn want<'a>(&'a self, cx: &'a DiskContext<'_>) -> Option<(&'a str, &'a Path)> {
        match &self.entry {
            Entry::Current => cx
                .current_disk
                .map(|view| (view.view_id.as_str(), view.image.as_path())),
            Entry::Dump(id) => self
                .dumps
                .iter()
                .find(|row| &row.dump.id == id && row.browsable())
                .map(|row| (row.dump.id.as_str(), row.image.as_path())),
        }
    }

    fn make_bound(&self, cx: &DiskContext<'_>) -> Option<Bound> {
        match &self.entry {
            Entry::Current => cx.current_disk.map(|view| Bound {
                key: view.view_id.clone(),
                image: view.image.clone(),
                extract_dir: view.extract_dir.clone(),
                what: What::Current(Box::new(view.clone())),
            }),
            Entry::Dump(id) => self
                .dumps
                .iter()
                .find(|row| &row.dump.id == id && row.browsable())
                .map(|row| Bound {
                    key: row.dump.id.clone(),
                    image: row.image.clone(),
                    extract_dir: row.dump.extract_dir(),
                    what: What::Dump,
                }),
        }
    }

    fn bind(&mut self, ctx: &egui::Context, bound: Bound) {
        self.start_readers(ctx, &bound);
        self.tree.reset();
        self.tree.hide_dotfiles = self.settings.hide_dotfiles;
        self.queue_browse(Purpose::Probe, DiskRequest::Probe, None);
        self.bound = Some(bound);
    }

    /// The same view now reads a different file (it was kept as a dump): new
    /// readers on the new path, the tree and selection stay.
    fn rebind(&mut self, ctx: &egui::Context, cx: &DiskContext<'_>) {
        let Some(bound) = self.make_bound(cx) else {
            return;
        };
        self.browse_queue.clear();
        self.search_queue.clear();
        self.purposes.clear();
        self.start_readers(ctx, &bound);
        self.queue_browse(Purpose::Probe, DiskRequest::Probe, None);
        self.bound = Some(bound);
    }

    fn start_readers(&mut self, ctx: &egui::Context, bound: &Bound) {
        match (
            worker::Worker::start(
                ctx.clone(),
                "disk-browse",
                bound.image.clone(),
                bound.extract_dir.clone(),
            ),
            worker::Worker::start(
                ctx.clone(),
                "disk-search",
                bound.image.clone(),
                bound.extract_dir.clone(),
            ),
        ) {
            (Ok(browse), Ok(search)) => {
                self.browse = Some(browse);
                self.search = Some(search);
            }
            (Err(error), _) | (_, Err(error)) => self.status = Some((error, true)),
        }
    }

    fn unbind(&mut self) {
        self.bound = None;
        self.browse = None;
        self.search = None;
        self.browse_queue.clear();
        self.search_queue.clear();
        self.purposes.clear();
        self.tree.reset();
        self.selection = None;
        self.probe = None;
        self.find = find::Find::default();
        self.extraction = Default::default();
        self.status = None;
    }

    fn token(&mut self, purpose: Purpose) -> u64 {
        self.next_token += 1;
        self.purposes.insert(self.next_token, purpose);
        self.next_token
    }

    fn queue_browse(&mut self, purpose: Purpose, request: DiskRequest, place: Option<String>) {
        let token = self.token(purpose);
        self.browse_queue.push((
            token,
            worker::Job {
                token,
                request,
                place,
            },
        ));
    }

    fn queue_search(&mut self, purpose: Purpose, request: DiskRequest, place: Option<String>) {
        let token = self.token(purpose);
        self.search_queue.push((
            token,
            worker::Job {
                token,
                request,
                place,
            },
        ));
    }

    /// Send the next queued requests and take the answers.
    fn pump(&mut self, ctx: &egui::Context) {
        let mut answers = Vec::new();
        for worker in [&mut self.browse, &mut self.search].into_iter().flatten() {
            answers.extend(worker.poll());
        }
        for answer in answers {
            self.accept(answer);
        }
        // The tree asks for the folder it is waiting on, when the browser is idle.
        let browser_idle = self
            .browse
            .as_ref()
            .is_some_and(|worker| worker.busy.is_none());
        if browser_idle && self.browse_queue.is_empty() {
            if let Some((path, offset)) = self.tree.wanted() {
                self.queue_browse(
                    Purpose::List {
                        path: path.clone(),
                        offset,
                    },
                    DiskRequest::List { path, offset },
                    None,
                );
            }
        }
        if let Some(worker) = &mut self.browse {
            if worker.busy.is_none() && !self.browse_queue.is_empty() {
                let (_, job) = self.browse_queue.remove(0);
                worker.send(job);
            }
        }
        if let Some(worker) = &mut self.search {
            if worker.busy.is_none() && !self.search_queue.is_empty() {
                let (_, job) = self.search_queue.remove(0);
                worker.send(job);
            }
        }
        if self.tree.advance_reveal() {
            ctx.request_repaint();
        }
        if self
            .browse
            .as_ref()
            .is_some_and(|worker| worker.busy.is_some())
            || self
                .search
                .as_ref()
                .is_some_and(|worker| worker.busy.is_some())
            || !self.browse_queue.is_empty()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn accept(&mut self, answer: worker::Answer) {
        use antinomie_monitor_core::disks::reader::DiskAnswer;
        let Some(purpose) = self.purposes.remove(&answer.token) else {
            return;
        };
        let flat = answer
            .reply
            .and_then(|reply| reply.map_err(|error| error.to_string()));
        match (purpose, flat) {
            (Purpose::Probe, Ok(DiskAnswer::Probed(info))) => self.probe = Some(Ok(info)),
            (Purpose::Probe, Err(error)) => self.probe = Some(Err(error)),
            (Purpose::List { path, offset }, Ok(DiskAnswer::Listed(listing))) => {
                self.tree.accept(&path, offset, Ok(listing));
            }
            (Purpose::List { path, offset }, Err(error)) => {
                self.tree.accept(&path, offset, Err(error));
            }
            (Purpose::Info { path }, Ok(DiskAnswer::Info(info))) => {
                if let Some(selection) = self.selection.as_mut().filter(|s| s.path == path) {
                    selection.info = Some(Ok(info));
                }
            }
            (Purpose::Info { path }, Err(error)) => {
                if let Some(selection) = self.selection.as_mut().filter(|s| s.path == path) {
                    selection.info = Some(Err(error));
                }
            }
            (Purpose::Find, Ok(DiskAnswer::Found(results))) => self.find.finished(Ok(results)),
            (Purpose::Find, Err(error)) => self.find.finished(Err(error)),
            (Purpose::Extract { path, intent }, Ok(DiskAnswer::Extracted(receipt))) => {
                self.extraction_done(path, intent, Ok(receipt), answer.placed);
            }
            (Purpose::Extract { path, intent }, Err(error)) => {
                self.extraction_done(path, intent, Err(error), None);
            }
            (purpose, other) => {
                self.status = Some((
                    format!("Unexpected reader answer for {purpose:?}: {other:?}"),
                    true,
                ));
            }
        }
    }

    /// Select `path` and show its Details.
    fn select(&mut self, path: String) {
        self.selection = Some(Selection {
            path: path.clone(),
            info: None,
            hashed: false,
        });
        self.browse_queue
            .retain(|(token, _)| !matches!(self.purposes.get(token), Some(Purpose::Info { .. })));
        self.queue_browse(
            Purpose::Info { path: path.clone() },
            DiskRequest::Info { path, hash_cap: 0 },
            None,
        );
    }

    /// Ask the backend to measure the disk, once per state of the VM.
    fn measure_when_needed(&mut self, cx: &DiskContext<'_>) {
        let Some(vm) = cx.vm else {
            return;
        };
        let state = (vm.id.clone(), cx.vm_off);
        if cx.vm_off
            && cx.current_disk.is_none()
            && cx.measure.is_none()
            && cx.job.is_none()
            && !cx.other_job
            && self.waiting.is_none()
            && self.measured_for.as_ref() != Some(&state)
        {
            self.measured_for = Some(state);
            self.wait_for(true);
            self.action = Some(DiskAction::Measure);
        }
    }

    /// A request went to the backend; `view` when its answer is a view or a
    /// measurement.
    pub(super) fn wait_for(&mut self, view: bool) {
        self.waiting = Some(Instant::now());
        self.waiting_for_view = view;
    }

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        mut cx: DiskContext<'_>,
    ) -> Option<DiskAction> {
        self.sync(ui.ctx(), &cx);
        self.action = None;
        self.measure_when_needed(&cx);
        egui::SidePanel::left("disk_entries")
            .resizable(true)
            .default_width(230.0)
            .width_range(170.0..=480.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.entries(ui, &cx));
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                left: 10,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.main_pane(ui, &mut cx));
        self.import_window(ui.ctx(), &cx);
        self.action.take()
    }
}

#[cfg(test)]
mod tests;
