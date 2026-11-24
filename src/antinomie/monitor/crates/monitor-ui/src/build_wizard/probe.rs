// SPDX-License-Identifier: GPL-3.0-only
//! What the build wizard asks of the host: container engines, their builder
//! images, the toolchain chroot's size, the kernel cache and KVM.
//!
//! These were asked on the render thread, some of them (the engine status,
//! the image list, a walk of the chroot folder) with an external program or
//! thousands of files behind them. A worker asks now and keeps the core's own
//! engine cache warm; the pages that need the answers show a spinner until the
//! first one is in, and read the last answer after that.
//!
//! The same goes for which tools each build mode lacks and why a mode cannot
//! run. Those walk `PATH` (each missing tool is a visit to every directory,
//! slow where `PATH` lists Windows folders), so they were asked on every frame
//! of the Build mode page. They are asked here, for the wizard's current base,
//! and kept for [`TOOLS_KEEP`]: a tool installed meanwhile is seen on the next
//! ask after that, while a page is open.
use crate::background::Task;
use antinomie_monitor_core::{
    build::{self, BuildMode, Kind, ToolStatus, BUILD_PROFILES},
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
/// How long the tools found on `PATH` are kept before a walk of `PATH` asks again.
const TOOLS_KEEP: Duration = Duration::from_secs(30);
/// The core keeps an engine's status for 20 s; an answer older than this is
/// no longer one the render thread can rely on finding in that cache.
const WARM: Duration = Duration::from_secs(16);

pub(super) type EngineImages = (Engine, Result<Vec<ImageInfo>, String>);

/// Every build mode, for the checks.
const MODES: [BuildMode; 5] = [
    BuildMode::Automatic,
    BuildMode::Native,
    BuildMode::Podman,
    BuildMode::Docker,
    BuildMode::Qemu,
];

/// What one build mode lacks for one base.
#[derive(Clone)]
pub(super) struct ModeCheck {
    pub mode: BuildMode,
    /// Host tools the mode needs and does not find (empty for a container mode).
    pub missing: Vec<ToolStatus>,
    /// Why the mode cannot run here, or `None` when it can.
    pub obstacle: Option<String>,
}

#[derive(Default)]
pub(super) struct Snapshot {
    /// The base the mode checks are for.
    pub kind: Option<Kind>,
    pub checks: Vec<ModeCheck>,
    /// When `PATH` was last walked for the checks.
    tools_at: Option<Instant>,
    pub toolchain_size: Option<u64>,
    pub images: Vec<EngineImages>,
    pub kernel_cached: Vec<(Kind, bool)>,
    pub kvm_problem: Option<String>,
}

impl Snapshot {
    pub(super) fn check(&self, mode: BuildMode) -> Option<&ModeCheck> {
        self.checks.iter().find(|check| check.mode == mode)
    }

    /// Where a build of the checked base runs for `mode`: the choice
    /// [`build::resolve_mode`] makes, from the kept answers.
    pub(super) fn resolve(&self, mode: BuildMode) -> Result<BuildMode, String> {
        build::resolve_mode_with(mode, |mode| {
            self.check(mode).and_then(|check| check.obstacle.clone())
        })
    }

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
    pub(super) fn tick(&mut self, ui: &egui::Ui, data_dir: &Path, kind: Kind) -> bool {
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
        // Answers for another base are no answers: ask again at once.
        let current = self.snapshot.kind == Some(kind);
        let due = !current || self.asked.is_none_or(|at| at.elapsed() >= REFRESH);
        if due && self.task.is_none() && self.removal.is_none() {
            let data_dir = data_dir.to_path_buf();
            // The tools on PATH of the last ask, while they are young.
            let kept = (current
                && self
                    .snapshot
                    .tools_at
                    .is_some_and(|at| at.elapsed() < TOOLS_KEEP))
            .then(|| (self.snapshot.checks.clone(), self.snapshot.tools_at));
            self.task = Some(Task::spawn(ctx, move || ask(&data_dir, kind, kept)));
        }
        ctx.request_repaint_after(REFRESH / 2);
        current && self.removal.is_none() && self.asked.is_some_and(|at| at.elapsed() < WARM)
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

/// The check of a mode that needs host tools: the kept one, or a new walk of `PATH`.
fn path_check(
    kind: Kind,
    mode: BuildMode,
    kept: &Option<(Vec<ModeCheck>, Option<Instant>)>,
) -> ModeCheck {
    if let Some(check) = kept
        .as_ref()
        .and_then(|(old, _)| old.iter().find(|check| check.mode == mode))
    {
        return check.clone();
    }
    ModeCheck {
        mode,
        missing: if mode == BuildMode::Automatic {
            Vec::new()
        } else {
            build::missing(kind, mode)
        },
        obstacle: build::mode_obstacle(kind, mode),
    }
}

/// The mode checks of `kind`. The tool lookups walk `PATH`; `kept` has the
/// last ones and when they were made, and is used instead of a new walk.
fn mode_checks(
    kind: Kind,
    kept: Option<(Vec<ModeCheck>, Option<Instant>)>,
) -> (Vec<ModeCheck>, Option<Instant>) {
    let stamp = kept
        .as_ref()
        .and_then(|(_, at)| *at)
        .unwrap_or_else(Instant::now);
    let checks = MODES
        .into_iter()
        .map(|mode| match mode.engine() {
            // A container mode asks only its engine, whose status the ask
            // before this one just refreshed.
            Some(_) => ModeCheck {
                mode,
                missing: Vec::new(),
                obstacle: build::mode_obstacle(kind, mode),
            },
            None => path_check(kind, mode, &kept),
        })
        .collect();
    (checks, Some(stamp))
}

fn ask(data_dir: &Path, kind: Kind, kept: Option<(Vec<ModeCheck>, Option<Instant>)>) -> Snapshot {
    let ready: Vec<Engine> = Engine::ALL
        .into_iter()
        .filter(|engine| container::refresh_standing(*engine).ready.is_ok())
        .collect();
    let images = ready
        .iter()
        .map(|engine| (*engine, container::list_images(*engine, &SystemRunner)))
        .collect();
    let chroot = toolchain::chroot_dir(&data_dir.join("build"));
    let (checks, tools_at) = mode_checks(kind, kept);
    Snapshot {
        kind: Some(kind),
        checks,
        tools_at,
        toolchain_size: chroot.exists().then(|| toolchain::size(&chroot)),
        images,
        kernel_cached: BUILD_PROFILES
            .iter()
            .map(|profile| (profile.kind, build::kernel_cached(data_dir, profile.kind)))
            .collect(),
        kvm_problem: antinomie_monitor_core::accel::kvm_problem(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(mode: BuildMode, obstacle: Option<&str>) -> ModeCheck {
        ModeCheck {
            mode,
            missing: Vec::new(),
            obstacle: obstacle.map(str::to_string),
        }
    }

    #[test]
    fn the_snapshot_resolves_a_mode_from_its_kept_checks() {
        let snapshot = Snapshot {
            kind: Some(Kind::BusyBox),
            checks: vec![
                check(BuildMode::Automatic, None),
                check(BuildMode::Native, Some("missing host tools: qemu-img")),
                check(BuildMode::Podman, Some("no engine")),
                check(BuildMode::Docker, None),
                check(BuildMode::Qemu, None),
            ],
            ..Snapshot::default()
        };
        assert_eq!(
            snapshot.resolve(BuildMode::Automatic),
            Ok(BuildMode::Docker)
        );
        assert_eq!(
            snapshot.resolve(BuildMode::Native),
            Err("missing host tools: qemu-img".into())
        );
        assert_eq!(snapshot.resolve(BuildMode::Qemu), Ok(BuildMode::Qemu));
        assert!(snapshot.check(BuildMode::Podman).is_some());
    }

    #[test]
    fn tools_found_on_path_are_kept_instead_of_walking_path_again() {
        let walked = Instant::now();
        let kept = Some((
            vec![check(BuildMode::Native, Some("kept answer"))],
            Some(walked),
        ));
        let again = path_check(Kind::BusyBox, BuildMode::Native, &kept);
        assert_eq!(again.obstacle.as_deref(), Some("kept answer"));
        // A mode that was not kept is asked.
        let fresh = path_check(Kind::BusyBox, BuildMode::Qemu, &kept);
        assert_ne!(fresh.obstacle.as_deref(), Some("kept answer"));
    }
}
