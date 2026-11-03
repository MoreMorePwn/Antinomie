// SPDX-License-Identifier: GPL-3.0-only
//! The wait for a systemd guest to finish booting before the first program of
//! a boot is launched, and what `run.json` records of it.
//!
//! A run started the moment the control channel is ready can beat systemd:
//! persistence such as `@reboot` cron then starts a second copy of the
//! program after the recording began, outside it.
use serde::{Deserialize, Serialize};

/// How the wait ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootWaitOutcome {
    /// The guest had finished booting (systemd's start-up job queue was
    /// empty, whether or not every unit succeeded).
    Ready,
    /// The guest was still booting when the wait ran out; the program was
    /// started anyway.
    Timeout,
    /// No wait applied: the guest is not systemd, or cannot be asked.
    Skipped,
}

/// The boot wait of one run, as `run.json` has it (`boot_wait`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootWait {
    /// Milliseconds between asking and the answer.
    pub waited_ms: u64,
    pub outcome: BootWaitOutcome,
    /// Why nothing was waited for, or what the timeout was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl BootWait {
    /// The note a run carries when the guest was still booting at launch.
    pub fn timeout_note(&self) -> Option<String> {
        (self.outcome == BootWaitOutcome::Timeout).then(|| {
            format!(
                "The guest had not finished booting after {} s; the program was started anyway. \
                 Services that start late (for example @reboot cron entries the program installed) \
                 may have started a second copy outside this recording.",
                self.waited_ms / 1000
            )
        })
    }
}

/// What the app shows while the wait goes on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchWait {
    pub program: String,
    pub started_ms: u64,
    pub text: String,
}

/// The status text of a launch waiting for the boot.
pub const WAIT_TEXT: &str = "Starting run: waiting for the guest to finish booting";
