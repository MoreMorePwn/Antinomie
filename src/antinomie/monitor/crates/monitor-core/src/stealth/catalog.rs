// SPDX-License-Identifier: GPL-3.0-only
//! The real machines a stealth profile can look like: business desktops and
//! laptops, common consumer laptops and small servers, each with the strings
//! such a unit reports (vendor, model, BIOS version and date, chassis type,
//! board), the CPU generations it shipped with and its onboard network card.
//!
//! Only factual identifiers, as any hardware inventory tool prints them: no
//! logos, firmware images, dumped ACPI tables (SLIC, MSDM) or real serial
//! numbers. The names belong to their owners; nothing here is endorsed by
//! them. Every value comes from public hardware reports of real units
//! (linuxhw DMI, Dmesg, HWInfo and SMART), cited in `catalog/SOURCES.md`.
use super::parts::{DiskModel, RamPart};
use super::{CpuGen, HostCpu, NicSlot, StealthPreset};

mod dell_desktops;
mod dell_laptops;
mod hp_desktops;
mod hp_laptops;
mod lenovo_desktops;
mod lenovo_laptops;
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

/// The SMBIOS fields QEMU fills with its own values when a launch leaves them
/// out, as the model's firmware writes them: the most common value in the
/// model's public dmidecode reports. An empty string is SMBIOS string 0,
/// which dmidecode prints as "Not Specified".
pub(super) struct SmbiosFields {
    /// Base board (type 2) versions; `#` stands for a digit of a per-unit
    /// number, drawn at random.
    pub(super) board_versions: &'static [&'static str],
    pub(super) board_location: &'static str,
    /// Chassis (type 3) version and SKU.
    pub(super) chassis_version: &'static str,
    pub(super) chassis_sku: &'static str,
    /// Processor (type 4) socket designation and part number.
    pub(super) cpu_socket: &'static str,
    pub(super) cpu_part: &'static str,
    /// Processor upgrade (socket) code of SMBIOS type 4: 0x01 other, 0x06
    /// none, 0x31 AM4, 0x32 LGA1151, 0x37 SP3, 0x3e LGA1200; and the voltage
    /// in tenths of a volt the units report (it differs by CPU).
    pub(super) cpu_upgrade: u8,
    pub(super) cpu_voltage: u8,
    /// Memory device (type 17) locator and bank locator of each slot of one
    /// real unit, the slot a single module sits in first.
    pub(super) dimm_slots: &'static [(&'static str, &'static str)],
    /// SMBIOS memory type detail bits: 0x0080 synchronous, 0x4080 also
    /// unbuffered, 0x2080 registered.
    pub(super) dimm_detail: u16,
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
    pub(super) fields: SmbiosFields,
    /// SATA disks seen in real units of the model (or, where they have none,
    /// of a sibling; see `catalog/SOURCES.md`), the first the likeliest.
    pub(super) disks: &'static [&'static DiskModel],
    /// Memory modules seen in real units of the model, as their firmware
    /// names them (Dell writes the JEDEC maker code, HP and Lenovo a name).
    pub(super) memory: &'static [RamPart],
    /// The optical drive's ATA model, for a machine that has one.
    pub(super) cdrom_model: &'static str,
    /// The onboard network card's chip, as the maker's documentation says.
    pub nic_chip: &'static str,
    pub(super) nic_subsystem: Subsystem,
    /// Where the QEMU card goes: the chipset's LAN place when the machine has
    /// one, else the ICH's (a root port would be QEMU's Red Hat one).
    pub(super) nic_slot: NicSlot,
    /// An optical drive in the chassis.
    pub(super) cdrom: bool,
}

/// How the emulated card (QEMU's Intel 82574L, driver e1000e) compares with
/// the chip the machine has. QEMU 11 emulates no Realtek PCIe or Broadcom
/// chip; its RTL8139 (10ec:8139, 100 Mbit PCI) is on no catalog machine and
/// shows only in VMs, so it would be the stronger giveaway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NicFit {
    /// The machine's chip uses the e1000e driver (I219, 82574L).
    Same,
    /// Another Intel chip (I210, driver igb): the guest kernel has no igb,
    /// which is QEMU's other real Intel card.
    OtherIntel,
    /// A Realtek or Broadcom chip.
    OtherMaker,
}

impl NicFit {
    /// The giveaway this leaves, if any.
    pub fn giveaway(self) -> Option<&'static str> {
        match self {
            Self::Same => None,
            Self::OtherIntel => {
                Some("network chip is Intel 82574L, the machine's is another Intel chip")
            }
            Self::OtherMaker => {
                Some("network chip is Intel 82574L, the machine's is a Realtek or Broadcom chip")
            }
        }
    }
}

impl MachineProfile {
    /// How the VM's card compares with this machine's network chip.
    pub fn nic_fit(&self) -> NicFit {
        if self.nic_chip.contains("I219") || self.nic_chip.contains("82574") {
            NicFit::Same
        } else if self.nic_chip.starts_with("Intel") {
            NicFit::OtherIntel
        } else {
            NicFit::OtherMaker
        }
    }

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
    dell_desktops::DELL_OPTIPLEX_7090,
    hp_desktops::HP_ELITEDESK_800_G6,
    lenovo_desktops::LENOVO_M75Q_GEN2,
    hp_desktops::HP_ELITEDESK_805_G8,
    dell_laptops::DELL_LATITUDE_5420,
    lenovo_laptops::LENOVO_T14_GEN3_AMD,
    servers::SUPERMICRO_X11SCL,
    servers::SUPERMICRO_H12SSL,
    dell_desktops::DELL_OPTIPLEX_7080,
    dell_desktops::DELL_OPTIPLEX_5090,
    dell_desktops::DELL_OPTIPLEX_3080,
    dell_desktops::DELL_OPTIPLEX_7000,
    hp_desktops::HP_ELITEDESK_800_G8,
    hp_desktops::HP_PRODESK_400_G7,
    hp_desktops::HP_PRODESK_600_G6,
    lenovo_desktops::LENOVO_THINKCENTRE_M70S_GEN3,
    lenovo_desktops::LENOVO_THINKCENTRE_NEO_50S_GEN3,
    lenovo_desktops::LENOVO_THINKCENTRE_M920S,
    hp_desktops::HP_PRODESK_405_G6,
    lenovo_desktops::LENOVO_THINKCENTRE_M75S_GEN2,
    dell_laptops::DELL_LATITUDE_5430,
    dell_laptops::DELL_LATITUDE_5520,
    dell_laptops::DELL_LATITUDE_5530,
    dell_laptops::DELL_LATITUDE_3520,
    dell_laptops::DELL_VOSTRO_15_3510,
    hp_laptops::HP_250_G8,
    hp_laptops::HP_PROBOOK_450_G8,
    hp_laptops::HP_PROBOOK_440_G8,
    lenovo_laptops::LENOVO_THINKPAD_T14_GEN3,
    lenovo_laptops::LENOVO_THINKPAD_E14_GEN4,
    lenovo_laptops::LENOVO_THINKPAD_L14_GEN2,
    hp_laptops::HP_PROBOOK_455_G8,
    lenovo_laptops::LENOVO_THINKPAD_E15_GEN3_AMD,
    lenovo_laptops::LENOVO_THINKPAD_L14_GEN2_AMD,
    lenovo_laptops::LENOVO_THINKPAD_T14_GEN2_AMD,
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
