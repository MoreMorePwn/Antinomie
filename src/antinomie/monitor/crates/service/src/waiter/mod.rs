// SPDX-License-Identifier: GPL-3.0-only
//! The engine waiter (design 4.1, 5.6; audit E17, G5): the one place a
//! process that owns a `Backend` and has no window sends commands and waits
//! for what they cause.
//!
//! The engine talks through two queues. Command results must be drained or
//! the owner fails; snapshots may be dropped, so only the latest matters;
//! terminal output is dropped when its lane is full, so it must be read.
//! [`Waiter`] drains continuously, keeps the latest [`Snapshot`], remembers
//! results by command id, and keeps a bounded tail of each run's terminal.
//!
//! Time comes from a [`Clock`], so tests move a [`ManualClock`] and never
//! sleep (design 7.2).
//!
//! [`ManualClock`]: crate::clock::ManualClock
use crate::clock::Clock;
use antinomie_monitor_core::{
    Command, Notification, RunSummary, Snapshot,
    analysis::{AnalysisReport, AnalysisState},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

mod run;
#[cfg(test)]
mod tests;
pub mod trigger;

pub use run::{
    BOOT_WAIT, EVIDENCE_WAIT, EndReason, Evidence, LAUNCH_WAIT, Phase, RunPlan, RunReport,
    STOP_RUN_GRACE, Timings, UPLOAD_WAIT, Warning, incomplete_parts, load_artifacts,
    may_stay_pending, pending_parts, phase,
};
pub(crate) use run::{Stop, late_launch_warning, route_of};

/// A guest command (upload, launch, stop run) whose result does not arrive in
/// this long at KVM speed is an `internal` failure of the engine (audit G5,
/// E17). Under TCG it is stretched like the engine's own waits on the guest
/// ([`Waiter::lane_silence`]), and the time the engine reports waiting for the
/// guest to finish booting does not count.
pub const LANE_SILENCE: Duration = Duration::from_secs(60);

/// Terminal bytes kept per run: the end of the output, enough to see why a
/// program stopped, small enough to leave in a result.
pub const TERMINAL_TAIL: usize = 64 * 1024;

pub use crate::engine::Engine;

/// Why a wait ended without the thing waited for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitError {
    /// The engine refused or failed the command; its own words.
    Failed(String),
    /// The time given ran out while the operation was still going.
    TimedOut { what: String },
    /// A guest command got no result within [`Waiter::lane_silence`]
    /// (`seconds`) while the engine reported no work on it.
    Silent { what: String, seconds: u64 },
    /// A signal asked the command to stop.
    Interrupted,
    /// The deadline the caller set for the whole command passed.
    DeadlineExceeded,
    /// The job was cancelled while the lane waited (a cancel hook is armed).
    Cancelled,
    /// The engine is gone.
    Disconnected(String),
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(message) | Self::Disconnected(message) => f.write_str(message),
            Self::TimedOut { what } => write!(f, "timed out waiting for {what}"),
            Self::Silent { what, seconds } => write!(
                f,
                "the engine did not answer {what} within {seconds} seconds"
            ),
            Self::Interrupted => f.write_str("interrupted"),
            Self::DeadlineExceeded => f.write_str("the time limit of the command passed"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for WaitError {}

/// The end of one run's terminal output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TerminalTail {
    pub bytes: Vec<u8>,
    /// Bytes that arrived before the kept ones.
    pub dropped: u64,
    pub eof: bool,
}

type Observer = Box<dyn FnMut(&Snapshot) + Send>;

pub struct Waiter<E: Engine> {
    engine: E,
    clock: Arc<dyn Clock>,
    snapshot: Snapshot,
    results: HashMap<u64, (bool, String)>,
    terminals: BTreeMap<String, TerminalTail>,
    observer: Option<Observer>,
    interrupted: Option<Box<dyn Fn() -> bool + Send>>,
    deadline_ms: Option<u64>,
    cancel: Option<Box<dyn FnMut() -> bool + Send>>,
    cancel_seen: bool,
    cancel_interrupts: bool,
    abandoned: Vec<u64>,
    /// An `Execute` given up as silent: the program may still start.
    pub(crate) unanswered_launch: Option<UnansweredLaunch>,
    /// Standalone analyses as `AnalysisUpdated` last told them: the snapshot
    /// keeps only eight, and a host worker waits for its own.
    analyses: HashMap<String, AnalysisReport>,
}

/// An `Execute` whose answer did not come in time, and the runs that were
/// there before it: a run that appears later is that launch's
/// ([`Waiter::late_launch`]).
#[derive(Clone, Debug)]
pub(crate) struct UnansweredLaunch {
    pub id: u64,
    pub known: Vec<String>,
}

impl<E: Engine> Waiter<E> {
    pub fn new(engine: E, clock: Arc<dyn Clock>) -> Self {
        Self {
            engine,
            clock,
            snapshot: Snapshot::default(),
            results: HashMap::new(),
            terminals: BTreeMap::new(),
            observer: None,
            interrupted: None,
            deadline_ms: None,
            cancel: None,
            cancel_seen: false,
            cancel_interrupts: false,
            abandoned: Vec::new(),
            unanswered_launch: None,
            analyses: HashMap::new(),
        }
    }

    /// Called with every snapshot as it arrives (progress lines).
    pub fn observe(&mut self, observer: impl FnMut(&Snapshot) + Send + 'static) {
        self.observer = Some(Box::new(observer));
    }

    /// Polled in every wait; true makes the wait end with
    /// [`WaitError::Interrupted`].
    pub fn interrupt_when(&mut self, interrupted: impl Fn() -> bool + Send + 'static) {
        self.interrupted = Some(Box::new(interrupted));
    }

    /// Every wait ends with [`WaitError::DeadlineExceeded`] once the clock
    /// passes `after` from now: the limit of the whole command.
    pub fn deadline_in(&mut self, after: Duration) {
        self.deadline_ms = Some(self.now_ms() + millis(after));
    }

    /// Forget the deadline of [`deadline_in`](Self::deadline_in): a cleanup
    /// after the watchdog fired must be able to wait.
    pub fn clear_deadline(&mut self) {
        self.deadline_ms = None;
    }

    /// Arm a cancel hook (design 4.1: cancellation is polled inside waits).
    /// `poll` is called in every wait; once it has said true the request is
    /// remembered ([`cancel_requested`](Self::cancel_requested)). While
    /// `interrupts` is true the wait also ends with [`WaitError::Cancelled`].
    pub fn cancel_when(&mut self, interrupts: bool, poll: impl FnMut() -> bool + Send + 'static) {
        self.cancel = Some(Box::new(poll));
        self.cancel_seen = false;
        self.cancel_interrupts = interrupts;
    }

    /// Drop the cancel hook and the request it saw.
    pub fn clear_cancel(&mut self) {
        self.cancel = None;
        self.cancel_seen = false;
        self.cancel_interrupts = false;
    }

    /// Whether waits end with [`WaitError::Cancelled`] once a cancel is seen.
    /// The run and collect stages turn it off and act on the request
    /// themselves: they must still stop the run and the VM.
    pub fn set_cancel_interrupts(&mut self, interrupts: bool) {
        self.cancel_interrupts = interrupts;
    }

    /// Has a cancel been asked for (polls the hook)?
    pub fn cancel_requested(&mut self) -> bool {
        if !self.cancel_seen
            && let Some(poll) = self.cancel.as_mut()
        {
            self.cancel_seen = poll();
        }
        self.cancel_seen
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    pub fn into_engine(self) -> E {
        self.engine
    }

    /// The terminal output kept for `run_id`.
    pub fn terminal(&self, run_id: &str) -> Option<&TerminalTail> {
        self.terminals.get(run_id)
    }

    fn check_interrupt(&mut self) -> Result<(), WaitError> {
        match &self.interrupted {
            Some(interrupted) if interrupted() => return Err(WaitError::Interrupted),
            _ => {}
        }
        if self.cancel_interrupts && self.cancel_requested() {
            return Err(WaitError::Cancelled);
        }
        match self.deadline_ms {
            Some(deadline) if self.now_ms() >= deadline => Err(WaitError::DeadlineExceeded),
            _ => Ok(()),
        }
    }

    /// Take the next notification within `timeout` and keep what it carries:
    /// the snapshot, a command result, a piece of terminal output. The
    /// notification is returned for a caller that wants to look at it too.
    pub fn pump(&mut self, timeout: Duration) -> Result<Option<Notification>, WaitError> {
        self.check_interrupt()?;
        let notification = self.engine.recv(timeout).map_err(WaitError::Disconnected)?;
        match &notification {
            Some(Notification::Snapshot(snapshot)) => {
                self.snapshot = snapshot.clone();
                if let Some(observer) = self.observer.as_mut() {
                    observer(&self.snapshot);
                }
            }
            Some(Notification::CommandResult {
                id,
                success,
                message,
            }) if *id > 0 => {
                self.results.insert(*id, (*success, message.clone()));
            }
            Some(Notification::AnalysisUpdated {
                run_id: None,
                report,
            }) => {
                if self.analyses.len() >= 64 {
                    self.analyses.clear();
                }
                self.analyses.insert(report.id.clone(), report.clone());
            }
            Some(Notification::Terminal {
                run_id, data, eof, ..
            }) => {
                let tail = self.terminals.entry(run_id.clone()).or_default();
                tail.bytes.extend_from_slice(data);
                if tail.bytes.len() > TERMINAL_TAIL {
                    let excess = tail.bytes.len() - TERMINAL_TAIL;
                    tail.bytes.drain(..excess);
                    tail.dropped += excess as u64;
                }
                tail.eof |= *eof;
            }
            _ => {}
        }
        Ok(notification)
    }

    /// Take everything the engine has queued, without waiting.
    pub fn drain(&mut self) -> Result<(), WaitError> {
        while self.pump(Duration::ZERO)?.is_some() {}
        Ok(())
    }

    /// Send a command; its id.
    pub fn send(&mut self, command: Command) -> Result<u64, WaitError> {
        self.engine.send(command).map_err(WaitError::Failed)
    }

    /// The result of command `id` if it has arrived.
    pub fn take_result(&mut self, id: u64) -> Option<Result<String, WaitError>> {
        self.results.remove(&id).map(|(success, message)| {
            if success {
                Ok(message)
            } else {
                Err(WaitError::Failed(message))
            }
        })
    }

    /// Send `command` and wait for its result. `limit` is how long the caller
    /// is willing to wait; `None` waits for as long as the engine works,
    /// because the worker owns the operation until it ends (a base import or a
    /// VM creation can take minutes, and a frontend deadline could neither
    /// cancel it nor report its outcome truthfully).
    pub fn command(
        &mut self,
        command: Command,
        limit: Option<Duration>,
    ) -> Result<String, WaitError> {
        let name = command_name(&command);
        let id = self.send(command)?;
        let deadline = limit.map(|limit| self.now_ms() + millis(limit));
        loop {
            if let Some(result) = self.take_result(id) {
                return result;
            }
            if deadline.is_some_and(|deadline| self.now_ms() >= deadline) {
                return Err(WaitError::TimedOut { what: name });
            }
            if let Err(error) = self.pump(Duration::from_millis(200)) {
                // The engine still works on the command: a caller that cleans
                // up must wait for it ([`finish_abandoned`](Self::finish_abandoned)).
                if matches!(
                    error,
                    WaitError::Interrupted | WaitError::Cancelled | WaitError::DeadlineExceeded
                ) {
                    self.abandoned.push(id);
                }
                return Err(error);
            }
        }
    }

    /// `Start`, or `RestoreVmSnapshot` (which boots the VM inside the command):
    /// `silence` is a silence
    /// limit, not a total. Under TCG the engine publishes a note while it
    /// waits for the guest to connect (`Snapshot::start_note`, from its own
    /// scaled wait), so while that note stands the engine is working and the
    /// silence counts from its end; the accelerator is only known once the
    /// engine has published it, so the stretch needs no multiplier of ours.
    /// Under KVM, and before the VM is up, nothing is stretched: `silence`
    /// passes as it would for [`command`](Self::command). A stuck engine still
    /// fails: [`START_HARD_WAIT`] bounds the whole command. Both ends are
    /// [`WaitError::TimedOut`].
    pub fn start_command(
        &mut self,
        command: Command,
        silence: Duration,
    ) -> Result<String, WaitError> {
        let name = command_name(&command);
        let id = self.send(command)?;
        let began = self.now_ms();
        let mut quiet_from = began;
        loop {
            if let Some(result) = self.take_result(id) {
                return result;
            }
            let now = self.now_ms();
            if self.guest_wait_factor() > 1.0 && self.snapshot.start_note.is_some() {
                quiet_from = now;
            }
            if now.saturating_sub(quiet_from) >= millis(silence)
                || now.saturating_sub(began) >= millis(START_HARD_WAIT)
            {
                // The engine still works on it: a cleanup waits for it.
                self.abandoned.push(id);
                return Err(WaitError::TimedOut { what: name });
            }
            if let Err(error) = self.pump(Duration::from_millis(200)) {
                if matches!(
                    error,
                    WaitError::Interrupted | WaitError::Cancelled | WaitError::DeadlineExceeded
                ) {
                    self.abandoned.push(id);
                }
                return Err(error);
            }
        }
    }

    /// Wait for the results of commands a cancel, a signal or the job limit
    /// made the caller stop waiting for. The engine finishes them anyway (a
    /// restore starts the VM after we gave up), so a cleanup that looks at the
    /// VM must wait for them first.
    pub fn finish_abandoned(&mut self, limit: Duration) -> Result<(), WaitError> {
        let deadline = self.now_ms() + millis(limit);
        while let Some(&id) = self.abandoned.first() {
            if self.results.remove(&id).is_some() {
                self.abandoned.remove(0);
                continue;
            }
            if self.now_ms() >= deadline {
                self.abandoned.clear();
                return Err(WaitError::TimedOut {
                    what: "a command that was given up".into(),
                });
            }
            self.pump(Duration::from_millis(200))?;
        }
        Ok(())
    }

    /// How many times longer than at KVM speed the guest may take to answer
    /// on the running boot: the engine's own factor (`accel::Waits`, the TCG
    /// multiplier times the host load under TCG), 1 under KVM or before a
    /// boot.
    pub fn guest_wait_factor(&self) -> f64 {
        self.snapshot
            .accelerator
            .as_ref()
            .map_or(1.0, |accelerator| accelerator.guest_wait_factor)
            .max(1.0)
    }

    /// `base`, a wait on the guest at KVM speed, stretched for this boot.
    pub fn guest_wait(&self, base: Duration) -> Duration {
        base.mul_f64(self.guest_wait_factor())
    }

    /// [`LANE_SILENCE`] for the running boot.
    pub fn lane_silence(&self) -> Duration {
        self.guest_wait(LANE_SILENCE)
    }

    /// A command to the guest: no result within [`lane_silence`] means the
    /// engine is stuck, which is `internal`, not a slow guest. While the
    /// engine reports that a launch waits for the guest to finish booting
    /// (`Snapshot::launch_wait`, up to the boot wait times the TCG multiplier)
    /// it is working, so the silence counts from the end of that wait.
    ///
    /// [`lane_silence`]: Self::lane_silence
    pub fn lane_command(&mut self, command: Command) -> Result<String, WaitError> {
        let name = command_name(&command);
        let id = self.send(command)?;
        self.lane_wait(id, name)
    }

    /// The wait of [`lane_command`](Self::lane_command) for the command `id`
    /// already sent.
    pub(crate) fn lane_wait(&mut self, id: u64, name: String) -> Result<String, WaitError> {
        let silence = self.lane_silence();
        let mut quiet_from = self.now_ms();
        loop {
            if let Some(result) = self.take_result(id) {
                return result;
            }
            if self.snapshot.launch_wait.is_some() {
                quiet_from = self.now_ms();
            }
            if self.now_ms().saturating_sub(quiet_from) >= millis(silence) {
                // The engine may still finish it: a cleanup waits for it.
                self.abandoned.push(id);
                return Err(WaitError::Silent {
                    what: name,
                    seconds: silence.as_secs(),
                });
            }
            if let Err(error) = self.pump(Duration::from_millis(200)) {
                if matches!(
                    error,
                    WaitError::Interrupted | WaitError::Cancelled | WaitError::DeadlineExceeded
                ) {
                    self.abandoned.push(id);
                }
                return Err(error);
            }
        }
    }

    /// The run of an `Execute` that was given up as silent and started after
    /// all, once the engine has answered it (call after the VM was stopped:
    /// the engine handles a stop after the launch it is busy with). `None`
    /// when no launch was given up or it started nothing. Asked once.
    pub fn late_launch(&mut self) -> Option<RunSummary> {
        let launch = self.unanswered_launch.take()?;
        let _ = self.drain();
        self.results.remove(&launch.id);
        self.snapshot
            .runs
            .iter()
            .find(|run| !launch.known.contains(&run.id))
            .cloned()
    }

    /// Wait for `pause` to pass, keeping the snapshot current (a pump returns
    /// at the first notification; this does not).
    pub fn pause(&mut self, pause: Duration) -> Result<(), WaitError> {
        let until = self.now_ms() + millis(pause);
        while self.now_ms() < until {
            let left = until.saturating_sub(self.now_ms());
            self.pump(Duration::from_millis(left.min(200)))?;
        }
        Ok(())
    }

    /// Wait until `done` holds for the latest snapshot. `what` names the wait
    /// in a timeout.
    pub fn wait_until(
        &mut self,
        what: &str,
        limit: Option<Duration>,
        mut done: impl FnMut(&Snapshot) -> bool,
    ) -> Result<(), WaitError> {
        let deadline = limit.map(|limit| self.now_ms() + millis(limit));
        loop {
            self.drain()?;
            if done(&self.snapshot) {
                return Ok(());
            }
            if deadline.is_some_and(|deadline| self.now_ms() >= deadline) {
                return Err(WaitError::TimedOut { what: what.into() });
            }
            self.pump(Duration::from_millis(100))?;
        }
    }

    /// The standalone analysis `id` as last seen: in the snapshot, or in the
    /// engine's `AnalysisUpdated` notices (whichever has it finished).
    pub fn analysis(&self, id: &str) -> Option<AnalysisReport> {
        let done = |r: &AnalysisReport| {
            !matches!(
                r.state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            )
        };
        let seen = self
            .snapshot
            .analysis_reports
            .iter()
            .find(|r| r.id == id)
            .cloned();
        let noticed = self.analyses.get(id).cloned();
        match (seen, noticed) {
            (Some(a), _) if done(&a) => Some(a),
            (_, Some(b)) if done(&b) => Some(b),
            (Some(a), _) => Some(a),
            (None, b) => b,
        }
    }

    /// Wait until the standalone analysis `id` satisfies `done`, for at most
    /// `limit`.
    pub fn wait_until_report(
        &mut self,
        what: &str,
        limit: Duration,
        id: &str,
        mut done: impl FnMut(&AnalysisReport) -> bool,
    ) -> Result<(), WaitError> {
        let deadline = self.now_ms() + millis(limit);
        loop {
            self.drain()?;
            if self.analysis(id).is_some_and(|r| done(&r)) {
                return Ok(());
            }
            if self.now_ms() >= deadline {
                return Err(WaitError::TimedOut { what: what.into() });
            }
            self.pump(Duration::from_millis(100))?;
        }
    }

    /// Wait for the engine's first snapshot after it started.
    pub fn first_snapshot(&mut self, limit: Duration) -> Result<(), WaitError> {
        let deadline = self.now_ms() + millis(limit);
        loop {
            if matches!(
                self.pump(Duration::from_millis(200))?,
                Some(Notification::Snapshot(_))
            ) {
                return Ok(());
            }
            if self.now_ms() >= deadline {
                return Ok(());
            }
        }
    }
}

/// The hard bound of a `Start` whose progress keeps its silence limit from
/// running out ([`Waiter::start_command`]).
pub const START_HARD_WAIT: Duration = Duration::from_secs(1800);

/// Longest a stop, its recording flush and the disk layer behind it may take
/// (design 4.1, `layer_s`).
pub const SETTLE_WAIT: Duration = Duration::from_secs(1800);

/// The VM is stopped, its recordings are saved and no disk layer of it is
/// pending: the recording is final (design 5.12.2).
pub fn settled_after_stop(snapshot: &Snapshot, vm_id: &str) -> bool {
    snapshot.state == antinomie_monitor_core::VmState::Stopped
        && snapshot.recording_flush.is_none()
        && !snapshot
            .disk_layers
            .iter()
            .any(|layer| layer.vm_id == vm_id)
}

impl<E: Engine> Waiter<E> {
    /// Stop the running VM and wait until its recording is final. `limit`
    /// bounds the wait for the layer; the stop itself is the engine's.
    pub fn stop_vm(&mut self, vm_id: &str, limit: Option<Duration>) -> Result<String, WaitError> {
        let message = self.command(Command::Stop, None)?;
        let vm = vm_id.to_owned();
        self.wait_until(
            "the recording to settle after the stop",
            Some(limit.unwrap_or(SETTLE_WAIT)),
            |snapshot| settled_after_stop(snapshot, &vm),
        )?;
        Ok(message)
    }
}

pub(crate) fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The variant name of a command, for messages (never its fields: a command
/// may carry a password).
pub fn command_name(command: &Command) -> String {
    let text = format!("{command:?}");
    text.split(['(', ' ', '{'])
        .next()
        .unwrap_or("command")
        .to_owned()
}
