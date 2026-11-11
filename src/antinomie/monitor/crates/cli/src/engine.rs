// SPDX-License-Identifier: GPL-3.0-only
//! Direct mode (design 2.2): this process takes the data-directory lock, runs
//! the engine in-process and exits. The engine and its waits are the service
//! crate's [`Waiter`]; this wrapper adds what only a command line needs: the
//! owner claim, the tool check before a command, progress lines on standard
//! error, SIGINT, and the mapping of engine failures to exit codes.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    logging::Logger,
    signals,
};
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, Notification, Snapshot,
    data_owner::{OwnerClaim, OwnerKind},
    dependencies,
};
use antinomie_service::{
    clock::SystemClock,
    waiter::{WaitError, Waiter},
};
use std::{path::PathBuf, sync::Arc, time::Duration};

/// How long the first snapshot may take after the engine started.
const FIRST_SNAPSHOT: Duration = Duration::from_secs(30);

pub struct DirectEngine {
    waiter: Waiter<Backend>,
    data_dir: PathBuf,
    options: BackendOptions,
}

impl DirectEngine {
    /// Start the engine as a `cli` owner of the data directory. A directory
    /// another process owns is `unavailable` (exit 21) and names the owner.
    pub fn start(context: &Context) -> Result<Self, CliError> {
        Self::start_lane(context, None)
    }

    /// [`start`](Self::start) on lane `lane`'s data folder (`<data>/lanes/N/`,
    /// ANT-T0455 card C): the lane engine shares the data folder's bases,
    /// library and settings. `None` and lane 1 are the data folder itself.
    pub fn start_lane(
        context: &Context,
        lane: Option<&antinomie_service::api::ids::LaneId>,
    ) -> Result<Self, CliError> {
        if context.mode() == crate::args::Mode::Daemon {
            return Err(CliError::new(
                ErrorCode::Unsupported,
                "the daemon serves the `auto` commands, the reads (`run list/show/export`, `triage`, `sample list/show/tag`, `custody verify`) and `vm list` and `base list`; this command runs in its own process (leave out --daemon, and stop the daemon or use another --data-dir while it owns this one)",
            ));
        }
        let mut options = context.options.clone();
        options.owner = OwnerClaim {
            kind: OwnerKind::Cli,
            socket: None,
            lane: None,
        };
        if let Some(lane) = lane.filter(|lane| lane.as_str() != "lane-1") {
            let root = &options.data_dir;
            let canonical = std::fs::canonicalize(root).map_err(|e| CliError::io(root, &e))?;
            options.data_dir = canonical;
            options = antinomie_service::daemon::lanes::lane_options(&options, lane);
        }
        let data_dir = options.data_dir.clone();
        let backend = Backend::new(options.clone())
            .map_err(|message| CliError::from_engine_start(&data_dir, &message))?;
        signals::install();
        let mut waiter = Waiter::new(backend, Arc::new(SystemClock));
        waiter.interrupt_when(signals::interrupted);
        waiter.observe(progress(context.logger));
        let mut engine = Self {
            waiter,
            data_dir,
            options,
        };
        engine
            .waiter
            .first_snapshot(FIRST_SNAPSHOT)
            .map_err(wait_error)?;
        Ok(engine)
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    pub fn snapshot(&self) -> &Snapshot {
        self.waiter.snapshot()
    }

    pub fn waiter(&mut self) -> &mut Waiter<Backend> {
        &mut self.waiter
    }

    /// The next notification within `timeout`, keeping the snapshot current.
    pub fn pump(&mut self, timeout: Duration) -> Result<Option<Notification>, CliError> {
        self.waiter.pump(timeout).map_err(wait_error)
    }

    /// Fail with the missing tool named when `command` needs one that is
    /// absent, before the engine tries and fails halfway.
    pub fn require_tools(&self, command: &Command) -> Result<(), CliError> {
        let needed = dependencies::requirements(command, &self.options, self.snapshot());
        if needed.is_empty() {
            return Ok(());
        }
        dependencies::check(&self.options)
            .require(&needed)
            .map_err(|problem| CliError::new(ErrorCode::DependencyMissing, problem))
    }

    /// Send `command` and wait for its result. `limit` is how long the caller
    /// will wait; `None` waits as long as the engine works.
    pub fn command(
        &mut self,
        command: Command,
        limit: Option<Duration>,
    ) -> Result<String, CliError> {
        self.require_tools(&command)?;
        self.waiter.command(command, limit).map_err(wait_error)
    }

    pub fn wait_until(
        &mut self,
        what: &str,
        limit: Option<Duration>,
        done: impl FnMut(&Snapshot) -> bool,
    ) -> Result<(), CliError> {
        self.waiter
            .wait_until(what, limit, done)
            .map_err(wait_error)
    }

    /// Stop the engine, which stops a running VM, and release the directory.
    pub fn finish(self) {
        let mut backend = self.waiter.into_engine();
        let _ = backend.shutdown();
    }
}

/// An engine failure as the error object the command reports.
pub fn wait_error(error: WaitError) -> CliError {
    match error {
        WaitError::Failed(message) => engine_failure(&message),
        WaitError::TimedOut { what } => CliError::new(
            ErrorCode::Unavailable,
            format!("timed out waiting for {what}"),
        )
        .with_exit(Exit::WaitTimeout),
        silent @ WaitError::Silent { .. } => CliError::internal(silent.to_string()),
        WaitError::DeadlineExceeded => CliError::new(
            ErrorCode::Unavailable,
            "the time limit of the command (--timeout) passed; the VM was stopped",
        )
        .with_exit(Exit::WaitTimeout),
        WaitError::Interrupted => CliError::internal("interrupted").with_exit(Exit::Interrupted),
        WaitError::Cancelled => CliError::internal("cancelled"),
        WaitError::Disconnected(message) => CliError::internal(message),
    }
}

/// The engine reports failures as text. The phrases that mean something to a
/// script get their own codes; anything else is a refused precondition.
pub fn engine_failure(message: &str) -> CliError {
    let lower = message.to_ascii_lowercase();
    let code = if lower.starts_with("unknown ") || lower.contains("not found") {
        ErrorCode::NotFound
    } else if lower.contains("already exists") {
        ErrorCode::Conflict
    } else if lower.contains("permission denied") {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::PreconditionFailed
    };
    CliError::new(code, message)
}

/// Progress lines for the things the engine does for a long time: the steps of
/// a VM being made, a snapshot, a download. Each text is logged once when it
/// first appears.
fn progress(logger: Logger) -> impl FnMut(&Snapshot) + Send + 'static {
    // Texts are compared without their digits, so a counter ("3 s of up to
    // 20 s") is one line, not one a second.
    let key = |text: &str| {
        text.chars()
            .filter(|c| !c.is_ascii_digit())
            .collect::<String>()
    };
    let mut seen: Vec<String> = Vec::new();
    move |snapshot| {
        let mut now: Vec<String> = Vec::new();
        for work in &snapshot.vm_work {
            now.push(format!("{}: {}", work.name, work.step));
        }
        if let Some(progress) = &snapshot.vm_snapshot_progress {
            now.push(format!("snapshot {}: {}", progress.vm_id, progress.stage));
        }
        if let Some(layout) = &snapshot.base_layout {
            now.push(format!("base {}: {}", layout.base, layout.stage));
        }
        if let Some(note) = &snapshot.start_note {
            now.push(note.clone());
        }
        if let Some(build) = &snapshot.build {
            now.push(format!("build {}: {}", build.label, build.stage));
        }
        if let Some(download) = &snapshot.download
            && download.total > 0
        {
            now.push(format!(
                "download {}: {}%",
                download.label,
                (download.received.saturating_mul(100) / download.total) / 10 * 10
            ));
        }
        for text in &now {
            if !seen.contains(&key(text)) {
                logger.info(text);
            }
        }
        seen = now.iter().map(|text| key(text)).collect();
    }
}
