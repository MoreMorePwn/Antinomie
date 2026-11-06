// SPDX-License-Identifier: GPL-3.0-only
//! The clock model of the boot age: how the guest kernel's first-launch step
//! treats CLOCK_MONOTONIC (docs/implementation/bases-and-stealth.md, "Aged
//! uptime").

use serde::{Deserialize, Serialize};

use super::{BootAge, StealthProfile};

/// Which clocks the boot age steps at the first program launch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockModel {
    /// The profile's machine decides, and so does the base: see
    /// [`StealthProfile::resolved_clock`].
    #[default]
    Auto,
    /// The machine never stopped: CLOCK_BOOTTIME and CLOCK_MONOTONIC both
    /// step by the age.
    Continuous,
    /// The age is time asleep: only CLOCK_BOOTTIME steps.
    Suspend,
}

impl ClockModel {
    /// The word the guest kernel takes on its command line.
    pub fn guest_word(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            _ => "continuous",
        }
    }
}

impl StealthProfile {
    /// The model the boot age runs with, never `Auto`. An explicit choice
    /// wins. Auto: a base that runs Debian's modules (systemd) gets
    /// `Suspend`, because stepping CLOCK_MONOTONIC makes systemd's watchdogs
    /// kill journald, udevd and logind at the first launch; elsewhere a
    /// server or cloud machine is `Continuous` and a desktop or laptop
    /// `Suspend`.
    pub fn resolved_clock(&self, debian: bool) -> ClockModel {
        match self.clock_model {
            ClockModel::Auto if debian => ClockModel::Suspend,
            ClockModel::Auto => match BootAge::of(self) {
                BootAge::Server => ClockModel::Continuous,
                BootAge::Desktop => ClockModel::Suspend,
            },
            chosen => chosen,
        }
    }

    /// The guest's clock model word for the boot age (see
    /// [`resolved_clock`](Self::resolved_clock)).
    pub fn boot_clock(&self, debian: bool) -> &'static str {
        self.resolved_clock(debian).guest_word()
    }
}
