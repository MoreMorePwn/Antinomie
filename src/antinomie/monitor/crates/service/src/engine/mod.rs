// SPDX-License-Identifier: GPL-3.0-only
//! The seam between the pipeline and the engine (design 7.1).
//!
//! `Backend` is a concrete struct that owns a thread, QEMU and the data
//! directory. Everything above it (the waiter, the lane stages, recovery)
//! talks to it through [`Engine`], so the whole pipeline runs without a VM
//! against [`FakeEngine`](fake::FakeEngine), which replays a script or one of
//! the traces the P0-1 spike recorded on a real machine
//! ([`trace`]).
use antinomie_monitor_core::{Backend, Command, Notification};
use std::time::Duration;

pub mod fake;
pub mod mux;
#[cfg(test)]
mod mux_tests;
pub mod trace;

pub use fake::FakeEngine;
pub use mux::{Handle, Mux};

#[cfg(test)]
mod tests;

/// What a caller needs from an engine: send a command, take notifications,
/// stop.
pub trait Engine {
    /// Queue `command`; the id its `CommandResult` will carry.
    fn send(&mut self, command: Command) -> Result<u64, String>;

    /// The next notification within `timeout`, or `None`. An `Err` means the
    /// engine is gone (its owner thread ended); nothing more will arrive.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String>;

    /// Stop the engine and release the data directory. The default does
    /// nothing, for engines with nothing to release.
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }

    /// Name `actor` in the custody entries the engine writes on its own
    /// thread (the push record, the run's start and end) until it is set
    /// again; `None` is `app`. The actor belongs to this engine alone, so
    /// every lane names its own job's caller (BH-29). The default keeps
    /// nothing, for engines that write no custody.
    fn set_custody_actor(&mut self, actor: Option<&str>) -> Result<(), String> {
        let _ = actor;
        Ok(())
    }
}

impl Engine for Backend {
    fn send(&mut self, command: Command) -> Result<u64, String> {
        Backend::send(self, command)
    }
    fn recv(&mut self, timeout: Duration) -> Result<Option<Notification>, String> {
        self.recv_timeout(timeout)
    }
    fn shutdown(&mut self) -> Result<(), String> {
        Backend::shutdown(self)
    }
    fn set_custody_actor(&mut self, actor: Option<&str>) -> Result<(), String> {
        Backend::set_custody_actor(self, actor)
    }
}
