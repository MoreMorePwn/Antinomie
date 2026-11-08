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
use antinomie_monitor_core::{Backend, Command, Notification, Snapshot};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
mod tests;

/// A guest command (upload, launch, stop run) whose result does not arrive in
/// this long is an `internal` failure of the engine (audit G5, E17).
pub const LANE_SILENCE: Duration = Duration::from_secs(60);

/// Terminal bytes kept per run: the end of the output, enough to see why a
/// program stopped, small enough to leave in a result.
pub const TERMINAL_TAIL: usize = 64 * 1024;

/// How the waiter talks to an engine. `Backend` is the real one; tests script
/// a fake.
pub trait Engine {
    fn send(&mut self, command: Command) -> Result<u64, String>;
    /// The next notification within `timeout`, or `None`.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String>;
}

impl Engine for Backend {
    fn send(&mut self, command: Command) -> Result<u64, String> {
        Backend::send(self, command)
    }
    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String> {
        self.recv_timeout(timeout)
    }
}

/// Why a wait ended without the thing waited for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitError {
    /// The engine refused or failed the command; its own words.
    Failed(String),
    /// The time given ran out while the operation was still going.
    TimedOut { what: String },
    /// A guest command got no result within [`LANE_SILENCE`].
    Silent { what: String },
    /// A signal asked the command to stop.
    Interrupted,
    /// The engine is gone.
    Disconnected(String),
}

impl std::fmt::Display for WaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(message) | Self::Disconnected(message) => f.write_str(message),
            Self::TimedOut { what } => write!(f, "timed out waiting for {what}"),
            Self::Silent { what } => write!(
                f,
                "the engine did not answer {what} within {} seconds",
                LANE_SILENCE.as_secs()
            ),
            Self::Interrupted => f.write_str("interrupted"),
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

    fn check_interrupt(&self) -> Result<(), WaitError> {
        match &self.interrupted {
            Some(interrupted) if interrupted() => Err(WaitError::Interrupted),
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
            self.pump(Duration::from_millis(200))?;
        }
    }

    /// A command to the guest: no result within [`LANE_SILENCE`] means the
    /// engine is stuck, which is `internal`, not a slow guest.
    pub fn lane_command(&mut self, command: Command) -> Result<String, WaitError> {
        let name = command_name(&command);
        self.command(command, Some(LANE_SILENCE))
            .map_err(|error| match error {
                WaitError::TimedOut { .. } => WaitError::Silent { what: name },
                other => other,
            })
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
