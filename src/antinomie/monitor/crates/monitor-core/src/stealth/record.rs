// SPDX-License-Identifier: GPL-3.0-only
//! The machine a run's guest looked like, saved with the run so a result can
//! be read against the identity it was seen under.
use super::{HostCpu, MACHINES, StealthProfile};
use serde::{Deserialize, Serialize};

/// The identity a VM showed when a run started. Serial numbers, the UUID and
/// the MAC address are left out: they are random and say nothing about the
/// machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MachineRecord {
    /// The machine as a person would say it: "Dell OptiPlex 7090".
    pub machine: String,
    /// The catalog id, empty for a Transparent or edited profile.
    pub profile: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    pub system_product: String,
    pub system_sku: String,
    pub board_product: String,
    pub chassis_type: u8,
    pub disk_model: String,
    pub memory_part: String,
    /// The onboard network card's chip, when the machine is in the catalog.
    pub nic_chip: String,
    /// The generation of the host CPU that passthrough showed, when known.
    pub host_cpu: String,
    /// Set when that CPU did not ship in this machine.
    pub cpu_note: Option<String>,
}

impl MachineRecord {
    pub fn of(profile: &StealthProfile, host: &HostCpu) -> Self {
        let identity = &profile.identity;
        let known = MACHINES
            .iter()
            .find(|machine| machine.id == identity.profile && profile.identity_enabled);
        Self {
            machine: profile.machine_name(),
            profile: if profile.identity_enabled {
                identity.profile.clone()
            } else {
                String::new()
            },
            bios_vendor: identity.bios_vendor.clone(),
            bios_version: identity.bios_version.clone(),
            bios_date: identity.bios_date.clone(),
            system_product: identity.system_product.clone(),
            system_sku: identity.system_sku.clone(),
            board_product: identity.board_product.clone(),
            chassis_type: identity.chassis_type,
            disk_model: identity.disk_model.clone(),
            memory_part: identity.memory_part.clone(),
            nic_chip: known
                .map(|machine| machine.nic_chip.to_owned())
                .unwrap_or_default(),
            host_cpu: if profile.cpu_passthrough {
                host.generation
                    .map(|generation| generation.label().to_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            },
            cpu_note: profile.cpu_note(host),
        }
    }

    /// One line for the run's details: "Dell OptiPlex 7090, BIOS 1.4.3 of 01/07/2022".
    pub fn summary(&self) -> String {
        if self.bios_version.is_empty() {
            return self.machine.clone();
        }
        format!(
            "{}, BIOS {} of {}",
            self.machine, self.bios_version, self.bios_date
        )
    }
}
