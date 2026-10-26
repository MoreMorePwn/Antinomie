// SPDX-License-Identifier: GPL-3.0-only
//! The real machines a stealth profile can look like: business desktops and
//! laptops, common consumer laptops and small servers, each with the strings
//! such a unit reports (vendor, model, BIOS version and date, chassis type,
//! board), the CPU generations it shipped with and its onboard network card.
//!
//! Only factual identifiers, as any hardware inventory tool prints them: no
//! logos, firmware images, dumped ACPI tables (SLIC, MSDM) or real serial
//! numbers. The names belong to their owners; nothing here is endorsed by
//! them. The values come from public dmidecode reports and the makers'
//! published specifications, listed in the project's task records.
use super::{CpuGen, HostCpu, NicSlot, StealthPreset};

mod dell_laptops;
mod desktops;
mod hp_lenovo_laptops;
mod servers;

/// One real unit of a model: the product name and SKU the firmware reports,
/// the board's product code and the chassis type.
pub struct Variant {
    pub(super) product: &'static str,
    pub(super) sku: &'static str,
    pub(super) board: &'static str,
    pub(super) chassis: u8,
}

/// How the network card's PCI subsystem ID (the maker's, as a board's own card
/// has it) follows from the unit.
pub(super) enum Subsystem {
    /// Intel's own: no maker ID known.
    None,
    /// A fixed `vendor:device`.
    Fixed(&'static str),
    /// Dell's: vendor 1028 and the SKU as the device.
    DellSku,
    /// The maker's vendor ID and the board's code as the device.
    Board(&'static str),
}

#[derive(Clone, Copy)]
pub(super) enum SerialStyle {
    /// Dell service tag: 7 characters.
    Dell,
    /// HP desktop: country code and 7 more, 10 characters.
    Hp,
    /// HP laptop: country code and 7 more, 10 characters.
    HpLaptop,
    /// Lenovo desktop: 8 characters.
    Lenovo,
    /// Lenovo laptop and server: two letters and six more.
    LenovoThinkPad,
    /// Supermicro: a letter and 11 more.
    Supermicro,
}

/// A real machine whose firmware strings a preset copies.
pub struct MachineProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: StealthPreset,
    /// `GenuineIntel`, `AuthenticAMD`: presets pick a machine that matches
    /// the host CPU, which passthrough shows to the guest.
    pub cpu_vendor: &'static str,
    /// How common the model is, as a share of the random pick.
    pub weight: u8,
    /// The CPU generations the machine shipped with.
    pub cpus: &'static [CpuGen],
    pub(super) bios_vendor: &'static str,
    /// Real (version, date) pairs of its BIOS releases.
    pub(super) bios: &'static [(&'static str, &'static str)],
    pub(super) manufacturer: &'static str,
    pub(super) version: &'static str,
    pub(super) family: &'static str,
    pub(super) board_manufacturer: &'static str,
    pub(super) variants: &'static [Variant],
    pub(super) acpi: (&'static str, &'static str),
    pub(super) serial: SerialStyle,
    /// SMBIOS type 11 strings; `{sku}` stands for the unit's SKU.
    pub(super) oem_strings: &'static [&'static str],
    /// The onboard network card's chip, as the maker's documentation says.
    pub nic_chip: &'static str,
    pub(super) nic_subsystem: Subsystem,
    /// Where the QEMU card goes: the chipset's LAN place when the machine has
    /// one, else the ICH's (a root port would be QEMU's Red Hat one).
    pub(super) nic_slot: NicSlot,
    /// An optical drive in the chassis.
    pub(super) cdrom: bool,
}

impl MachineProfile {
    /// Whether a CPU of the host's generation shipped in this machine; None
    /// when the host's generation is not known.
    pub fn fits(&self, host: &HostCpu) -> Option<bool> {
        host.generation
            .map(|generation| self.cpus.contains(&generation))
    }

    /// The machine as a person would say it: "Dell OptiPlex 7090".
    pub fn name(&self) -> &'static str {
        self.label
    }
}

pub const MACHINES: &[MachineProfile] = &[
    desktops::DELL_OPTIPLEX_7090,
    desktops::HP_ELITEDESK_800_G6,
    desktops::LENOVO_M75Q_GEN2,
    desktops::HP_ELITEDESK_805_G8,
    dell_laptops::DELL_LATITUDE_5420,
    hp_lenovo_laptops::LENOVO_T14_GEN3_AMD,
    servers::SUPERMICRO_X12STH,
    servers::SUPERMICRO_H12SSL,
    desktops::DELL_OPTIPLEX_7080,
    desktops::DELL_OPTIPLEX_5090,
    desktops::DELL_OPTIPLEX_3080,
    desktops::DELL_OPTIPLEX_7000,
    desktops::HP_ELITEDESK_800_G8,
    desktops::HP_PRODESK_400_G7,
    desktops::HP_PRODESK_600_G6,
    desktops::LENOVO_THINKCENTRE_M70S_GEN3,
    desktops::LENOVO_THINKCENTRE_NEO_50S_GEN3,
    desktops::LENOVO_THINKCENTRE_M920S,
    desktops::HP_PRODESK_405_G6,
    desktops::LENOVO_THINKCENTRE_M75S_GEN2,
    dell_laptops::DELL_LATITUDE_5430,
    dell_laptops::DELL_LATITUDE_5520,
    dell_laptops::DELL_LATITUDE_5530,
    dell_laptops::DELL_LATITUDE_3520,
    dell_laptops::DELL_VOSTRO_15_3510,
    hp_lenovo_laptops::HP_250_G8,
    hp_lenovo_laptops::HP_PROBOOK_450_G8,
    hp_lenovo_laptops::HP_PROBOOK_440_G8,
    hp_lenovo_laptops::LENOVO_THINKPAD_T14_GEN3,
    hp_lenovo_laptops::LENOVO_THINKPAD_E14_GEN4,
    hp_lenovo_laptops::LENOVO_THINKPAD_L14_GEN2,
    hp_lenovo_laptops::HP_PROBOOK_455_G8,
    hp_lenovo_laptops::LENOVO_THINKPAD_E15_GEN3_AMD,
    hp_lenovo_laptops::LENOVO_THINKPAD_L14_GEN2_AMD,
    hp_lenovo_laptops::LENOVO_THINKPAD_T14_GEN2_AMD,
    servers::DELL_POWEREDGE_R240,
    servers::DELL_POWEREDGE_T140,
    servers::DELL_POWEREDGE_R350,
    servers::LENOVO_THINKSYSTEM_SR250_V2,
];

/// A machine for a new VM of `kind` on `host`, from `roll`: one of those whose
/// CPU generations include the host's (all of them when the host's is unknown),
/// the likelier for being a common model. The flag says whether the host's CPU
/// could be in it; it is false only when nothing of the kind fits the host.
pub(super) fn pick_machine(
    kind: StealthPreset,
    host: &HostCpu,
    roll: u32,
) -> (&'static MachineProfile, bool) {
    let of_kind = |vendor: bool| {
        MACHINES.iter().filter(move |machine| {
            machine.kind == kind && (!vendor || machine.cpu_vendor == host.vendor)
        })
    };
    let fitting: Vec<_> = of_kind(true)
        .filter(|machine| machine.fits(host) != Some(false))
        .collect();
    let (pool, fits): (Vec<_>, bool) = if !fitting.is_empty() {
        (fitting, true)
    } else {
        let same_vendor: Vec<_> = of_kind(true).collect();
        if same_vendor.is_empty() {
            (of_kind(false).collect(), false)
        } else {
            (same_vendor, false)
        }
    };
    let pool = if pool.is_empty() {
        MACHINES.iter().collect()
    } else {
        pool
    };
    let total: u32 = pool.iter().map(|machine| u32::from(machine.weight)).sum();
    let mut at = roll % total.max(1);
    for machine in &pool {
        let weight = u32::from(machine.weight);
        if at < weight {
            return (machine, fits);
        }
        at -= weight;
    }
    (pool[0], fits)
}
