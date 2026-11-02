// SPDX-License-Identifier: GPL-3.0-only
//! What the build wizard asks of the host: container engines, their builder
//! images, the toolchain chroot's size, the kernel cache and KVM.
//!
//! These were asked on the render thread, some of them (the engine status,
//! the image list, a walk of the chroot folder) with an external program or
//! thousands of files behind them. A worker asks now and keeps the core's own
//! engine cache warm; the pages that need the answers show a spinner until the
//! first one is in, and read the last answer after that.
use crate::background::Task;
use antinomie_monitor_core::{
    build::{self, Kind, BUILD_PROFILES},
    container::{self, Engine, ImageInfo, SystemRunner},
    toolchain,
};
use eframe::egui;
use std::{
    path::Path,
    time::{Duration, Instant},
};

/// Ask again this often while a page that needs the answers is open.
const REFRESH: Duration = Duration::from_secs(6);
/// The core keeps an engine's status for 20 s; an answer older than this is
/// no longer one the render thread can rely on finding in that cache.
const WARM: Duration = Duration::from_secs(16);

pub(super) type EngineImages = (Engine, Result<Vec<ImageInfo>, String>);

#[derive(Default)]
pub(super) struct Snapshot {
    pub toolchain_size: Option<u64>,
    pub images: Vec<EngineImages>,
    pub kernel_cached: Vec<(Kind, bool)>,
    pub kvm_problem: Option<String>,
}

impl Snapshot {
    pub(super) fn kernel_cached(&self, kind: Kind) -> bool {
        self.kernel_cached
            .iter()
            .any(|(known, cached)| *known == kind && *cached)
    }
}

#[derive(Default)]
pub(super) struct Probe {
    asked: Option<Instant>,
    task: Option<Task<Snapshot>>,
    pub snapshot: Snapshot,
    /// A removal (an image, the chroot) that is running, and its error label.
    removal: Option<(String, Task<Result<(), String>>)>,
}

impl Probe {
    /// Call every frame of a page that needs the answers: collects a finished
    /// ask, starts the next one when due, and says whether the answers can be
    /// used now.
    pub(super) fn tick(&mut self, ui: &egui::Ui, data_dir: &Path) -> bool {
        let ctx = ui.ctx();
        if let Some(task) = &self.task {
            if let Some(snapshot) = task.done() {
                self.snapshot = snapshot;
                self.task = None;
                self.asked = Some(Instant::now());
            }
        }
        if let Some((label, task)) = &self.removal {
            if let Some(result) = task.done() {
                if let Err(error) = result {
                    crate::activity::report(
                        ctx,
                        crate::activity::Level::Error,
                        format!("{label}: {error}"),
                    );
                }
                self.removal = None;
                container::forget_standing();
                self.asked = None;
            }
        }
        let due = self.asked.is_none_or(|at| at.elapsed() >= REFRESH);
        if due && self.task.is_none() && self.removal.is_none() {
            let data_dir = data_dir.to_path_buf();
            self.task = Some(Task::spawn(ctx, move || ask(&data_dir)));
        }
        ctx.request_repaint_after(REFRESH / 2);
        self.removal.is_none() && self.asked.is_some_and(|at| at.elapsed() < WARM)
    }

    /// Run `work` (a removal) on a worker; its error is shown as a toast.
    pub(super) fn remove(
        &mut self,
        ctx: &egui::Context,
        label: String,
        work: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) {
        if self.removal.is_none() {
            self.removal = Some((label, Task::spawn(ctx, work)));
        }
    }

    pub(super) fn removing(&self) -> bool {
        self.removal.is_some()
    }
}

fn ask(data_dir: &Path) -> Snapshot {
    let ready: Vec<Engine> = Engine::ALL
        .into_iter()
        .filter(|engine| container::refresh_standing(*engine).ready.is_ok())
        .collect();
    let images = ready
        .iter()
        .map(|engine| (*engine, container::list_images(*engine, &SystemRunner)))
        .collect();
    let chroot = toolchain::chroot_dir(&data_dir.join("build"));
    Snapshot {
        toolchain_size: chroot.exists().then(|| toolchain::size(&chroot)),
        images,
        kernel_cached: BUILD_PROFILES
            .iter()
            .map(|profile| (profile.kind, build::kernel_cached(data_dir, profile.kind)))
            .collect(),
        kvm_problem: antinomie_monitor_core::accel::kvm_problem(),
    }
}
