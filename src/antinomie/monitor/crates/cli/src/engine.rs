// SPDX-License-Identifier: GPL-3.0-only
//! Direct mode (design 2.2): this process takes the data-directory lock, runs
//! the engine in-process and exits. A small wrapper over `Backend` that sends a
//! command and waits for its result while keeping the latest snapshot.
//!
//! Card P1-5 plans a core-side `DirectEngine` for the base, VM and snapshot
//! commands; when it lands this wrapper should give way to it.
use crate::error::{CliError, ErrorCode};
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, Notification, Snapshot,
    data_owner::{OwnerClaim, OwnerKind},
};
use std::time::{Duration, Instant};

pub struct DirectEngine {
    backend: Backend,
    pub snapshot: Snapshot,
    data_dir: std::path::PathBuf,
}

/// How long the first snapshot may take after the engine started.
const FIRST_SNAPSHOT: Duration = Duration::from_secs(30);

impl DirectEngine {
    /// Start the engine as a `cli` owner of `options.data_dir`. A directory
    /// another process owns is `unavailable` (exit 21) and names the owner.
    pub fn start(mut options: BackendOptions) -> Result<Self, CliError> {
        options.owner = OwnerClaim {
            kind: OwnerKind::Cli,
            socket: None,
        };
        let data_dir = options.data_dir.clone();
        let backend = Backend::new(options)
            .map_err(|message| CliError::from_engine_start(&data_dir, &message))?;
        let mut engine = Self {
            backend,
            snapshot: Snapshot::default(),
            data_dir,
        };
        let deadline = Instant::now() + FIRST_SNAPSHOT;
        loop {
            match engine.next(Duration::from_millis(200)) {
                Some(Notification::Snapshot(_)) => break,
                _ if Instant::now() >= deadline => break,
                _ => {}
            }
        }
        Ok(engine)
    }

    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }

    /// The next notification within `timeout`, keeping the snapshot current.
    pub fn next(&mut self, timeout: Duration) -> Option<Notification> {
        let notification = self.backend.recv_timeout(timeout).ok().flatten()?;
        if let Notification::Snapshot(snapshot) = &notification {
            self.snapshot = snapshot.clone();
        }
        Some(notification)
    }

    /// Send `command` and wait for its result until `deadline`.
    pub fn command(&mut self, command: Command, deadline: Instant) -> Result<String, CliError> {
        let id = self
            .backend
            .send(command)
            .map_err(|message| CliError::new(ErrorCode::Internal, message))?;
        loop {
            match self.next(Duration::from_millis(200)) {
                Some(Notification::CommandResult {
                    id: reply,
                    success,
                    message,
                }) if reply == id => {
                    return if success {
                        Ok(message)
                    } else {
                        Err(CliError::new(ErrorCode::PreconditionFailed, message))
                    };
                }
                _ if Instant::now() >= deadline => {
                    return Err(CliError::new(
                        ErrorCode::Unavailable,
                        "the engine did not answer in time",
                    )
                    .with_exit(crate::exit::Exit::WaitTimeout));
                }
                _ => {}
            }
        }
    }

    /// Stop the engine and release the data directory.
    pub fn finish(mut self) {
        let _ = self.backend.shutdown();
    }
}
