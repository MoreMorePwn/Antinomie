// SPDX-License-Identifier: GPL-3.0-only
//! Library › Screenshots: the pictures taken on the VM screen tab, newest
//! first, across every VM's recording folder (`<recording folder>/screenshots`).
//! The folders are read on a thread when the page opens, on Refresh and after
//! a new screenshot; thumbnails are decoded by one worker thread, only for
//! the cells that are on screen, and kept in a bounded cache. A click opens
//! the picture in a window that fits it whole or shows it at 1:1.
use super::*;
use crate::widgets;
use chrono::TimeZone;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Sense, TextureOptions, Vec2};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender},
};

pub(crate) mod decode;
#[cfg(test)]
mod fixture;

/// The thumbnail cell: picture area and gap.
const THUMB_W: f32 = 224.0;
const THUMB_H: f32 = 126.0;
const GAP: f32 = 12.0;
/// Pixels wide a thumbnail is decoded to (twice the cell, for sharp scaling).
const THUMB_PX: usize = 448;
/// The longest side of a picture shown whole.
const FULL_PX: usize = 4096;
/// Thumbnails kept; the ones not drawn for longest go first.
const KEEP: usize = 240;

/// One screenshot file.
#[derive(Clone)]
struct Shot {
    path: PathBuf,
    vm_id: String,
    vm_name: String,
    /// When it was taken (Unix ms): from its name, else the file's time.
    ms: u64,
    /// The last run of the VM that began before it.
    run: Option<String>,
    /// A timed screenshot of a run: milliseconds from the run's start.
    rel_ms: Option<u64>,
}

/// A run with timed screenshots (`<run folder>/screenshots/t+SSSSSS.s.png`).
#[derive(Clone)]
struct TimedRun {
    vm_id: String,
    vm_name: String,
    label: String,
    started_ms: u64,
    directory: PathBuf,
}

/// What the scan needs of one VM.
struct Target {
    vm_id: String,
    vm_name: String,
    folders: Vec<PathBuf>,
}

enum Thumb {
    Loading,
    Ready(egui::TextureHandle),
    Failed,
}

enum Job {
    Thumb(PathBuf),
    Full(PathBuf),
}

enum Done {
    Thumb(PathBuf, Result<egui::ColorImage, String>),
    Full(PathBuf, Result<egui::ColorImage, String>),
}

/// The enlarged picture.
struct Viewer {
    shot: Shot,
    texture: Option<egui::TextureHandle>,
    error: Option<String>,
    one_to_one: bool,
}

/// What a cell or the viewer asks for.
enum Act {
    Open(PathBuf),
    Copy(PathBuf),
    Reveal(PathBuf),
    Delete(PathBuf),
}

pub(super) struct ScreenshotsPage {
    shots: Vec<Shot>,
    loaded: bool,
    stale: bool,
    scan: Option<Receiver<Vec<Shot>>>,
    thumbs: HashMap<PathBuf, (Thumb, u64)>,
    worker: Option<Sender<Job>>,
    done_tx: Sender<Done>,
    done: Receiver<Done>,
    frame: u64,
    viewer: Option<Viewer>,
    confirm: Option<Shot>,
    seen_saved: u64,
    /// The timed screenshots of the run the Summary shows, read again every
    /// couple of seconds (a run in progress adds to them).
    timed: Option<(
        String,
        std::time::Instant,
        Vec<antinomie_monitor_core::timed_shots::RunShot>,
    )>,
}

impl Default for ScreenshotsPage {
    fn default() -> Self {
        let (done_tx, done) = mpsc::channel();
        Self {
            shots: Vec::new(),
            loaded: false,
            stale: false,
            scan: None,
            thumbs: HashMap::new(),
            worker: None,
            done_tx,
            done,
            frame: 0,
            viewer: None,
            confirm: None,
            seen_saved: 0,
            timed: None,
        }
    }
}

fn time_text(ms: u64) -> String {
    chrono::Local
        .timestamp_millis_opt(ms as i64)
        .single()
        .map_or_else(String::new, |t| t.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// When a screenshot was taken: `vm-screen-YYYYmmdd-HHMMSS.png` says; any
/// other PNG goes by its file time.
fn taken_ms(path: &Path) -> u64 {
    let named = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.strip_prefix("vm-screen-"))
        .and_then(|stamp| chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S").ok())
        .and_then(|naive| chrono::Local.from_local_datetime(&naive).earliest())
        .and_then(|t| u64::try_from(t.timestamp_millis()).ok());
    named
        .or_else(|| {
            let modified = std::fs::metadata(path).ok()?.modified().ok()?;
            let since = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
            Some(since.as_millis() as u64)
        })
        .unwrap_or(0)
}

/// Read the screenshot folders of `targets`, newest first. `runs` are
/// (VM, start ms, label) of every known run.
fn scan(
    targets: Vec<Target>,
    mut runs: Vec<(String, u64, String)>,
    timed: Vec<TimedRun>,
) -> Vec<Shot> {
    runs.sort_by_key(|run| run.1);
    let mut seen = HashSet::new();
    let mut shots = Vec::new();
    for target in targets {
        for folder in target.folders {
            let Ok(entries) = std::fs::read_dir(folder.join("screenshots")) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_png = path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("png"));
                if !is_png || !seen.insert(path.clone()) {
                    continue;
                }
                let ms = taken_ms(&path);
                let run = runs
                    .iter()
                    .rev()
                    .find(|run| run.0 == target.vm_id && run.1 <= ms)
                    .map(|run| format!("after run {} ({})", run.2, time_text(run.1)));
                shots.push(Shot {
                    path,
                    vm_id: target.vm_id.clone(),
                    vm_name: target.vm_name.clone(),
                    ms,
                    run,
                    rel_ms: None,
                });
            }
        }
    }
    // The runs' own series: grouped by run, with the run-relative time.
    for run in timed {
        for found in antinomie_monitor_core::timed_shots::list(&run.directory) {
            if seen.insert(found.path.clone()) {
                shots.push(Shot {
                    path: found.path,
                    vm_id: run.vm_id.clone(),
                    vm_name: run.vm_name.clone(),
                    ms: run.started_ms + found.t_ms,
                    run: Some(format!(
                        "timed screenshots of run {} ({})",
                        run.label,
                        time_text(run.started_ms)
                    )),
                    rel_ms: Some(found.t_ms),
                });
            }
        }
    }
    shots.sort_by(|a, b| b.ms.cmp(&a.ms).then_with(|| a.path.cmp(&b.path)));
    shots
}

impl ScreenshotsPage {
    /// The timed screenshots of `run`, oldest first; none for a run that did
    /// not ask for them.
    pub(super) fn timed_for(
        &mut self,
        run: &antinomie_monitor_core::RunSummary,
    ) -> Vec<antinomie_monitor_core::timed_shots::RunShot> {
        if run.request.screenshot_every_s.is_none() {
            return Vec::new();
        }
        let stale = self.timed.as_ref().is_none_or(|(id, at, _)| {
            id != &run.id || at.elapsed() >= std::time::Duration::from_secs(2)
        });
        if stale {
            let shots = antinomie_monitor_core::timed_shots::list(&run.directory);
            self.timed = Some((run.id.clone(), std::time::Instant::now(), shots));
        }
        self.timed
            .as_ref()
            .map(|(_, _, shots)| shots.clone())
            .unwrap_or_default()
    }

    /// The sidebar count, once the folders were read.
    pub(super) fn count_text(&self) -> Option<String> {
        (self.loaded && !self.shots.is_empty()).then(|| self.shots.len().to_string())
    }

    /// The VM screen tab reports how many screenshots it saved: a new one
    /// means the folders changed.
    pub(super) fn saved(&mut self, total: u64) {
        if total != self.seen_saved {
            self.seen_saved = total;
            self.stale = true;
        }
    }

    fn send(&mut self, ctx: &egui::Context, job: Job) {
        let done = self.done_tx.clone();
        let sender = self.worker.get_or_insert_with(|| {
            let (sender, jobs) = mpsc::channel::<Job>();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for job in jobs {
                    let message = match job {
                        Job::Thumb(path) => {
                            let image = decode::load(&path, THUMB_PX);
                            Done::Thumb(path, image)
                        }
                        Job::Full(path) => {
                            let image = decode::load(&path, FULL_PX);
                            Done::Full(path, image)
                        }
                    };
                    if done.send(message).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
            });
            sender
        });
        let _ = sender.send(job);
    }

    /// Take in what the threads finished.
    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.scan {
            if let Ok(shots) = receiver.try_recv() {
                self.shots = shots;
                self.loaded = true;
                self.scan = None;
                let live: HashSet<&PathBuf> = self.shots.iter().map(|s| &s.path).collect();
                self.thumbs.retain(|path, _| live.contains(path));
            }
        }
        while let Ok(done) = self.done.try_recv() {
            match done {
                Done::Thumb(path, image) => {
                    if let Some(slot) = self.thumbs.get_mut(&path) {
                        slot.0 = match image {
                            Ok(image) => Thumb::Ready(ctx.load_texture(
                                format!("shot-thumb-{}", path.display()),
                                image,
                                TextureOptions::LINEAR,
                            )),
                            Err(_) => Thumb::Failed,
                        };
                    }
                }
                Done::Full(path, image) => {
                    if let Some(viewer) = self.viewer.as_mut().filter(|v| v.shot.path == path) {
                        match image {
                            Ok(image) => {
                                viewer.texture = Some(ctx.load_texture(
                                    format!("shot-full-{}", path.display()),
                                    image,
                                    TextureOptions::LINEAR,
                                ));
                            }
                            Err(error) => viewer.error = Some(error),
                        }
                    }
                }
            }
        }
        if self.thumbs.len() > KEEP {
            let mut used: Vec<(u64, PathBuf)> = self
                .thumbs
                .iter()
                .map(|(path, (_, frame))| (*frame, path.clone()))
                .collect();
            used.sort();
            for (frame, path) in used.into_iter().take(self.thumbs.len() - KEEP * 3 / 4) {
                if frame + 1 < self.frame {
                    self.thumbs.remove(&path);
                }
            }
        }
    }

    fn remove(&mut self, path: &Path) {
        self.shots.retain(|shot| shot.path != path);
        self.thumbs.remove(path);
        if self.viewer.as_ref().is_some_and(|v| v.shot.path == path) {
            self.viewer = None;
        }
    }

    /// The thumbnail of `path`: asks for it the first time it is drawn.
    fn thumb(&mut self, ctx: &egui::Context, path: &Path) -> Option<(egui::TextureId, [usize; 2])> {
        let frame = self.frame;
        if let Some((thumb, used)) = self.thumbs.get_mut(path) {
            *used = frame;
            return match thumb {
                Thumb::Ready(texture) => Some((texture.id(), texture.size())),
                _ => None,
            };
        }
        self.thumbs.insert(path.to_owned(), (Thumb::Loading, frame));
        self.send(ctx, Job::Thumb(path.to_owned()));
        None
    }

    fn thumb_failed(&self, path: &Path) -> bool {
        matches!(self.thumbs.get(path), Some((Thumb::Failed, _)))
    }

    fn open(&mut self, ctx: &egui::Context, shot: Shot) {
        self.send(ctx, Job::Full(shot.path.clone()));
        self.viewer = Some(Viewer {
            shot,
            texture: None,
            error: None,
            one_to_one: false,
        });
    }

    /// One thumbnail cell: the picture, its time and its three buttons.
    fn cell(&mut self, ui: &mut egui::Ui, shot: &Shot) -> Option<Act> {
        let mut act = None;
        ui.vertical(|ui| {
            ui.set_width(THUMB_W);
            let (rect, response) =
                ui.allocate_exact_size(Vec2::new(THUMB_W, THUMB_H), Sense::click());
            let hovered = response.hovered();
            ui.painter().rect_filled(rect, 4.0, Color32::BLACK);
            if ui.is_rect_visible(rect) {
                let ctx = ui.ctx().clone();
                match self.thumb(&ctx, &shot.path) {
                    Some((id, size)) => {
                        let image = Vec2::new(size[0] as f32, size[1] as f32);
                        let scale = (THUMB_W / image.x).min(THUMB_H / image.y);
                        ui.painter().image(
                            id,
                            Rect::from_center_size(rect.center(), image * scale),
                            Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
                            Color32::WHITE,
                        );
                    }
                    None => {
                        let (text, color) = if self.thumb_failed(&shot.path) {
                            ("cannot read this picture", theme::error())
                        } else {
                            ("loading…", theme::muted())
                        };
                        ui.painter().text(
                            rect.center(),
                            egui::Align2::CENTER_CENTER,
                            text,
                            egui::FontId::proportional(12.0),
                            color,
                        );
                    }
                }
            }
            if hovered {
                ui.painter().rect_stroke(
                    rect,
                    4.0,
                    egui::Stroke::new(2.0, theme::palette().accent),
                    egui::StrokeKind::Inside,
                );
            }
            let name = shot
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let response = response
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(format!("{name}\n{}", shot.path.display()));
            if response.clicked() {
                act = Some(Act::Open(shot.path.clone()));
            }
            match shot.rel_ms {
                Some(rel) => ui.label(
                    RichText::new(antinomie_monitor_core::timed_shots::time_label(rel))
                        .small()
                        .strong(),
                ),
                None => ui.label(RichText::new(time_text(shot.ms)).small()),
            };
            ui.horizontal(|ui| {
                if icon_button(ui, egui_phosphor::regular::COPY, "Copy the path") {
                    act = Some(Act::Copy(shot.path.clone()));
                }
                if icon_button(ui, egui_phosphor::regular::FOLDER_OPEN, "Open the folder") {
                    act = Some(Act::Reveal(shot.path.clone()));
                }
                if icon_button(ui, egui_phosphor::regular::TRASH, "Delete…") {
                    act = Some(Act::Delete(shot.path.clone()));
                }
            });
        });
        act
    }

    /// The gallery body: the VMs, each with its runs and thumbnails.
    fn gallery(&mut self, ui: &mut egui::Ui) -> Option<Act> {
        let mut act = None;
        let shots = self.shots.clone();
        let mut order: Vec<&str> = Vec::new();
        for shot in &shots {
            if !order.contains(&shot.vm_id.as_str()) {
                order.push(&shot.vm_id);
            }
        }
        let columns = (((ui.available_width() + GAP) / (THUMB_W + GAP)) as usize).max(1);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for vm in order {
                    let group: Vec<&Shot> = shots.iter().filter(|s| s.vm_id == vm).collect();
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&group[0].vm_name).strong());
                        ui.label(
                            RichText::new(count(group.len(), "screenshot")).color(theme::muted()),
                        );
                    });
                    let mut run: Option<&Option<String>> = None;
                    let mut index = 0;
                    while index < group.len() {
                        // One row of cells, within one run.
                        let current = &group[index].run;
                        if run != Some(current) {
                            ui.add_space(2.0);
                            ui.label(
                                RichText::new(
                                    current
                                        .as_deref()
                                        .unwrap_or("before any recorded run")
                                        .to_owned(),
                                )
                                .small()
                                .color(theme::muted()),
                            );
                            run = Some(current);
                        }
                        let end = (index..group.len().min(index + columns))
                            .take_while(|i| &group[*i].run == current)
                            .last()
                            .map_or(index + 1, |i| i + 1);
                        ui.horizontal_top(|ui| {
                            ui.spacing_mut().item_spacing.x = GAP;
                            for shot in &group[index..end] {
                                if let Some(found) = self.cell(ui, shot) {
                                    act = Some(found);
                                }
                            }
                        });
                        ui.add_space(8.0);
                        index = end;
                    }
                }
            });
        act
    }

    /// Open the picture `delta` places on from the open one, in time order
    /// within its VM and run group (the arrow keys); nothing at either end.
    fn step(&mut self, ctx: &egui::Context, delta: i32) {
        let Some(current) = self.viewer.as_ref().map(|viewer| viewer.shot.clone()) else {
            return;
        };
        let mut group: Vec<&Shot> = self
            .shots
            .iter()
            .filter(|shot| shot.vm_id == current.vm_id && shot.run == current.run)
            .collect();
        group.sort_by(|a, b| a.ms.cmp(&b.ms).then_with(|| a.path.cmp(&b.path)));
        let Some(at) = group.iter().position(|shot| shot.path == current.path) else {
            return;
        };
        let Some(next) = at
            .checked_add_signed(delta as isize)
            .and_then(|to| group.get(to))
            .map(|shot| (*shot).clone())
        else {
            return;
        };
        self.open(ctx, next);
    }

    /// The enlarged picture; its buttons come back as an action.
    fn viewer_window(&mut self, ctx: &egui::Context) -> Option<Act> {
        let mut act = None;
        if self.viewer.is_some() && !crate::typing::typing(ctx) {
            let step = ctx.input(|input| {
                i32::from(input.key_pressed(egui::Key::ArrowRight))
                    - i32::from(input.key_pressed(egui::Key::ArrowLeft))
            });
            if step != 0 {
                self.step(ctx, step);
            }
        }
        let viewer = self.viewer.as_mut()?;
        let mut open = true;
        let screen = ctx.content_rect().size();
        let name = viewer
            .shot
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        widgets::window(format!("Screenshot: {name}"))
            .id(egui::Id::new("screenshot_viewer"))
            .open(&mut open)
            .default_size(screen * 0.8)
            .min_size(Vec2::new(360.0, 240.0))
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut viewer.one_to_one, false, "Fit");
                    ui.selectable_value(&mut viewer.one_to_one, true, "1:1");
                    ui.separator();
                    let when = match viewer.shot.rel_ms {
                        Some(rel) => format!(
                            "{} into the run · {}",
                            antinomie_monitor_core::timed_shots::time_label(rel),
                            time_text(viewer.shot.ms)
                        ),
                        None => time_text(viewer.shot.ms),
                    };
                    ui.label(
                        RichText::new(format!("{} · {when}", viewer.shot.vm_name))
                            .color(theme::muted()),
                    );
                    if let Some(texture) = &viewer.texture {
                        let [w, h] = texture.size();
                        ui.label(RichText::new(format!("{w} x {h}")).color(theme::muted()));
                    }
                    if viewer.shot.rel_ms.is_some() {
                        ui.label(
                            RichText::new("Left/Right: previous/next in the run")
                                .color(theme::muted()),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Delete…").clicked() {
                            act = Some(Act::Delete(viewer.shot.path.clone()));
                        }
                        if ui.button("Open folder").clicked() {
                            act = Some(Act::Reveal(viewer.shot.path.clone()));
                        }
                        if ui.button("Copy path").clicked() {
                            act = Some(Act::Copy(viewer.shot.path.clone()));
                        }
                    });
                });
                ui.separator();
                let Some(texture) = viewer.texture.clone() else {
                    ui.centered_and_justified(|ui| match &viewer.error {
                        Some(error) => ui.colored_label(theme::error(), error),
                        None => theme::loading(ui, "Reading the picture…"),
                    });
                    return;
                };
                let ppp = ui.ctx().pixels_per_point();
                let [w, h] = texture.size();
                let native = Vec2::new(w as f32, h as f32) / ppp;
                let uv = Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0));
                if viewer.one_to_one {
                    egui::ScrollArea::both()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let (rect, _) = ui.allocate_exact_size(native, Sense::hover());
                            ui.painter().image(texture.id(), rect, uv, Color32::WHITE);
                        });
                } else {
                    let area = ui.available_size();
                    let (outer, _) = ui.allocate_exact_size(area, Sense::hover());
                    let scale = (area.x / native.x).min(area.y / native.y).clamp(0.01, 1.0);
                    ui.painter().rect_filled(outer, 0.0, Color32::BLACK);
                    ui.painter().image(
                        texture.id(),
                        Rect::from_center_size(outer.center(), native * scale),
                        uv,
                        Color32::WHITE,
                    );
                }
            });
        if !open {
            self.viewer = None;
        }
        act
    }
}

fn icon_button(ui: &mut egui::Ui, icon: &str, hint: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(icon).small()).frame(false))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint)
        .clicked()
}

impl MonitorApp {
    fn screenshot_scan(&mut self) {
        let names: HashMap<&str, &str> = self
            .snapshot
            .vms
            .iter()
            .map(|vm| (vm.id.as_str(), vm.name.as_str()))
            .collect();
        let targets: Vec<Target> = self
            .snapshot
            .vm_locations
            .iter()
            .map(|location| {
                let mut folders = vec![location.recording_directory.clone()];
                for folder in &location.recording_directories {
                    if !folders.contains(folder) {
                        folders.push(folder.clone());
                    }
                }
                Target {
                    vm_name: names
                        .get(location.vm_id.as_str())
                        .map_or_else(|| location.vm_id.clone(), |name| (*name).to_owned()),
                    vm_id: location.vm_id.clone(),
                    folders,
                }
            })
            .collect();
        let mut seen = HashSet::new();
        let runs: Vec<(String, u64, String)> = self
            .snapshot
            .runs
            .iter()
            .chain(self.history.iter())
            .filter(|run| seen.insert(run.id.clone()))
            .filter_map(|run| {
                let name = Path::new(&run.request.path).file_name()?;
                Some((
                    run.vm_id.clone(),
                    run.started_ms?,
                    name.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        let mut seen_timed = HashSet::new();
        let timed: Vec<TimedRun> = self
            .snapshot
            .runs
            .iter()
            .chain(self.history.iter())
            .filter(|run| run.request.screenshot_every_s.is_some())
            .filter(|run| seen_timed.insert(run.id.clone()))
            .filter_map(|run| {
                let label = Path::new(&run.request.path).file_name()?;
                Some(TimedRun {
                    vm_id: run.vm_id.clone(),
                    vm_name: names
                        .get(run.vm_id.as_str())
                        .map_or_else(|| run.vm_id.clone(), |name| (*name).to_owned()),
                    label: label.to_string_lossy().into_owned(),
                    started_ms: run.started_ms?,
                    directory: run.directory.clone(),
                })
            })
            .collect();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(scan(targets, runs, timed));
        });
        self.screenshots_page.scan = Some(receiver);
        self.screenshots_page.stale = false;
    }

    fn screenshot_act(&mut self, ctx: &egui::Context, act: Act) {
        match act {
            Act::Open(path) => {
                if let Some(shot) = self.screenshots_page.shots.iter().find(|s| s.path == path) {
                    let shot = shot.clone();
                    self.screenshots_page.open(ctx, shot);
                }
            }
            Act::Copy(path) => {
                ctx.copy_text(path.display().to_string());
                crate::toasts::notify(ctx, crate::activity::Level::Info, "Path copied");
            }
            Act::Reveal(path) => {
                if let Some(folder) = path.parent() {
                    crate::evidence::reveal(ctx, folder);
                }
            }
            Act::Delete(path) => {
                self.screenshots_page.confirm = self
                    .screenshots_page
                    .shots
                    .iter()
                    .find(|s| s.path == path)
                    .cloned();
            }
        }
    }

    /// Delete screenshot…: the file's name and where it is, then Delete.
    fn screenshot_confirm(&mut self, ctx: &egui::Context) {
        let Some(shot) = self.screenshots_page.confirm.clone() else {
            return;
        };
        let mut open = true;
        let mut delete = false;
        let mut cancel = false;
        widgets::window("Delete screenshot")
            .id(egui::Id::new("screenshot_delete"))
            .open(&mut open)
            .default_width(460.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "Delete this screenshot of {} from {}?",
                    shot.vm_name,
                    time_text(shot.ms)
                ));
                ui.label(RichText::new(shot.path.display().to_string()).color(theme::muted()));
                ui.label("The file is removed from the disk and cannot be restored.");
                widgets::footer_split(
                    ui,
                    |_| {},
                    |ui| {
                        if ui.button("Delete").clicked() {
                            delete = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    },
                );
            });
        if delete {
            match std::fs::remove_file(&shot.path) {
                Ok(()) => self.screenshots_page.remove(&shot.path),
                Err(error) => crate::toasts::notify(
                    ctx,
                    crate::activity::Level::Error,
                    format!("Could not delete the screenshot: {error}"),
                ),
            }
        }
        if delete || cancel || !open {
            self.screenshots_page.confirm = None;
        }
    }

    /// The Screenshots page body.
    pub(super) fn screenshots_page(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.screenshots_page.frame += 1;
        self.screenshots_page.poll(&ctx);
        if (!self.screenshots_page.loaded || self.screenshots_page.stale)
            && self.screenshots_page.scan.is_none()
        {
            self.screenshot_scan();
        }
        let page = &self.screenshots_page;
        let mut refresh = false;
        ui.horizontal(|ui| {
            if ui
                .button(format!(
                    "{} Refresh",
                    egui_phosphor::regular::ARROWS_CLOCKWISE
                ))
                .on_hover_text("Read the screenshot folders again")
                .clicked()
            {
                refresh = true;
            }
            if page.scan.is_some() {
                theme::spinner(ui);
            }
            if !page.shots.is_empty() {
                let vms = page.shots.iter().map(|s| &s.vm_id).collect::<HashSet<_>>();
                ui.label(
                    RichText::new(format!(
                        "{} in {}, newest first",
                        count(page.shots.len(), "screenshot"),
                        count(vms.len(), "VM")
                    ))
                    .color(theme::muted()),
                );
            }
        });
        ui.separator();
        let mut act = None;
        if self.screenshots_page.shots.is_empty() {
            if self.screenshots_page.loaded {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(egui_phosphor::regular::IMAGES).size(36.0));
                    ui.label(RichText::new("No screenshots yet").strong());
                    ui.label(
                        RichText::new(
                            "Start a VM that shows its screen in the app, open the VM screen \
                             tab and click Screenshot.",
                        )
                        .color(theme::muted()),
                    );
                    ui.label(
                        RichText::new(
                            "Each picture is saved in the VM's recording folder, under \
                             screenshots, and appears here.",
                        )
                        .color(theme::muted()),
                    );
                });
            } else {
                theme::loading(ui, "Reading the screenshot folders…");
            }
        } else {
            act = self.screenshots_page.gallery(ui);
        }
        if refresh {
            self.screenshots_page.stale = true;
        }
        if let Some(found) = self.screenshots_page.viewer_window(&ctx) {
            act = Some(found);
        }
        if let Some(act) = act {
            self.screenshot_act(&ctx, act);
        }
        self.screenshot_confirm(&ctx);
    }
}

/// "1 screenshot", "3 screenshots".
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

impl MonitorApp {
    /// The last screenshot taken on the VM screen tab during `run`: after it
    /// began and no later than a few seconds after its process tree ended.
    /// The folders are read once, on a thread, the first time this asks.
    pub(super) fn last_run_screenshot(
        &mut self,
        ctx: &egui::Context,
        run: &antinomie_monitor_core::RunSummary,
        ended_ms: Option<u64>,
    ) -> Option<PathBuf> {
        self.screenshots_page.poll(ctx);
        if !self.screenshots_page.loaded && self.screenshots_page.scan.is_none() {
            self.screenshot_scan();
        }
        let from = run.started_ms?;
        self.screenshots_page
            .shots
            .iter()
            .filter(|shot| shot.vm_id == run.vm_id && shot.ms >= from)
            .filter(|shot| ended_ms.is_none_or(|end| shot.ms <= end + 10_000))
            .max_by_key(|shot| shot.ms)
            .map(|shot| shot.path.clone())
    }

    /// Open `path` in the Screenshots page's viewer.
    pub(super) fn open_screenshot_path(&mut self, ctx: &egui::Context, path: PathBuf) {
        self.open_library(crate::workspace::LibraryPage::Screenshots);
        self.screenshot_act(ctx, Act::Open(path));
    }
}
