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
    /// The wait for the guest's network address that followed; absent in
    /// runs saved before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkWait>,
}

/// The wait for the guest to have its network address before the launch
/// (`boot_wait.network` in `run.json`). A Routed VM's gateway is the guest's
/// DHCP server and router, so the host sees when the guest has its address:
/// it sends from it, or answers the router's ARP for it. Until then every
/// connection of the program fails with ENETUNREACH.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkWait {
    pub waited_ms: u64,
    /// `Ready`: the guest had its address; `Timeout`: it had none when the
    /// wait ran out and the program was started anyway; `Skipped`: no wait.
    pub outcome: BootWaitOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The status text of a launch waiting for the guest's network.
pub const NETWORK_WAIT_TEXT: &str = "Starting run: waiting for the guest's network address";

impl NetworkWait {
    /// The note a run carries when it started without a network.
    pub fn timeout_note(&self) -> Option<String> {
        (self.outcome == BootWaitOutcome::Timeout).then(|| {
            format!(
                "The guest had no network address after {} s (the gateway saw no packet from the \
                 address its DHCP gives, and no answer to ARP for it); the program was started \
                 anyway, so its first connections may fail with \"network is unreachable\" \
                 (ENETUNREACH) and a program that kills the DHCP client leaves the run without a \
                 network.",
                self.waited_ms / 1000
            )
        })
    }
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
/// The text of an `AwaitBoot` wait (no program is waiting).
pub const BOOT_TEXT: &str = "Waiting for the guest to finish booting";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_that_started_without_a_network_says_so() {
        let wait = NetworkWait {
            waited_ms: 300_400,
            outcome: BootWaitOutcome::Timeout,
            detail: Some("gave up after 300 s".into()),
        };
        let note = wait.timeout_note().unwrap();
        assert!(
            note.starts_with("The guest had no network address after 300 s"),
            "{note}"
        );
        assert!(note.contains("ENETUNREACH"), "{note}");
        for outcome in [BootWaitOutcome::Ready, BootWaitOutcome::Skipped] {
            let quiet = NetworkWait {
                outcome,
                ..wait.clone()
            };
            assert_eq!(quiet.timeout_note(), None);
        }
    }

    #[test]
    fn a_boot_wait_saved_before_the_network_wait_still_reads() {
        let old: BootWait =
            serde_json::from_str(r#"{"waited_ms": 12, "outcome": "ready"}"#).unwrap();
        assert_eq!(old.network, None);
        let new = BootWait {
            network: Some(NetworkWait {
                waited_ms: 1_500,
                outcome: BootWaitOutcome::Ready,
                detail: None,
            }),
            ..old
        };
        let json = serde_json::to_value(&new).unwrap();
        assert_eq!(json["network"]["outcome"], "ready");
        assert_eq!(serde_json::from_value::<BootWait>(json).unwrap(), new);
    }
}
