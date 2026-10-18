// SPDX-License-Identifier: MIT
//! Stealth profile: QEMU launch options that make a VM look like ordinary
//! hardware to software that checks whether it runs in a VM.
//!
//! The profile is stored per VM. A preset fills every entry; serials, the
//! system UUID and the MAC address are random per VM and kept, so one VM keeps
//! its identity across boots and two VMs never share one. Everything here is
//! a launch option: the guest kernel's own traces (its command line, the
//! fw_cfg device, its build string) are outside this profile.
use crate::storage::unique_id;
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command};

/// A starting point for every entry; changing one makes the profile Custom.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum StealthPreset {
    RealisticDesktop,
    RealisticLaptop,
    RealisticServer,
    /// The launch Antinomie used before profiles: QEMU's own identity.
    #[default]
    Transparent,
    Custom,
}

impl StealthPreset {
    pub const ALL: &'static [Self] = &[
        Self::RealisticDesktop,
        Self::RealisticLaptop,
        Self::RealisticServer,
        Self::Transparent,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::RealisticDesktop => "Realistic desktop",
            Self::RealisticLaptop => "Realistic laptop",
            Self::RealisticServer => "Realistic server",
            Self::Transparent => "Transparent QEMU (as before)",
            Self::Custom => "Custom",
        }
    }
}

/// The emulated network card.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NicModel {
    /// Fastest; its Red Hat vendor ID is a VM giveaway.
    #[default]
    VirtioNet,
    /// Intel 82574L.
    E1000e,
    /// Intel 82540EM.
    E1000,
    /// Realtek RTL8139.
    Rtl8139,
}

impl NicModel {
    pub const ALL: &'static [Self] = &[Self::VirtioNet, Self::E1000e, Self::E1000, Self::Rtl8139];

    pub fn label(self) -> &'static str {
        match self {
            Self::VirtioNet => "virtio-net (fastest, VM vendor ID)",
            Self::E1000e => "Intel e1000e (82574L)",
            Self::E1000 => "Intel e1000 (82540EM)",
            Self::Rtl8139 => "Realtek RTL8139",
        }
    }

    fn device(self) -> &'static str {
        match self {
            Self::VirtioNet => "virtio-net-pci",
            Self::E1000e => "e1000e",
            Self::E1000 => "e1000",
            Self::Rtl8139 => "rtl8139",
        }
    }

    /// A vendor prefix real cards of this kind carry.
    fn mac_prefix(self) -> [u8; 3] {
        match self {
            Self::VirtioNet | Self::E1000e | Self::E1000 => [0x3c, 0xfd, 0xfe],
            Self::Rtl8139 => [0x00, 0xe0, 0x4c],
        }
    }
}

/// What the firmware tables, the CPU and the devices say about the machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MachineIdentity {
    /// The built-in profile these values came from, or empty when edited.
    pub profile: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    pub system_manufacturer: String,
    pub system_product: String,
    pub system_version: String,
    pub system_family: String,
    pub system_sku: String,
    pub system_serial: String,
    pub system_uuid: String,
    pub board_manufacturer: String,
    pub board_product: String,
    pub board_serial: String,
    /// SMBIOS chassis type: 3 desktop, 7 tower, 35 mini PC, 9 laptop,
    /// 10 notebook, 23 rack mount chassis.
    pub chassis_type: u8,
    pub chassis_serial: String,
    pub memory_manufacturer: String,
    pub memory_part: String,
    pub memory_serial: String,
    /// ACPI table header OEM ID (6 bytes) and OEM table ID (8 bytes).
    pub acpi_oem_id: String,
    pub acpi_table_id: String,
    pub cdrom_model: String,
    pub disk_serial: String,
}

/// The stealth profile of one VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StealthProfile {
    pub preset: StealthPreset,
    /// Firmware tables (SMBIOS, ACPI OEM IDs), CD-ROM and disk identity.
    pub identity_enabled: bool,
    pub identity: MachineIdentity,
    /// Pass the host CPU through (its real name and features); KVM only.
    pub cpu_passthrough: bool,
    /// Clear the CPUID hypervisor bit.
    pub hide_hypervisor: bool,
    /// Hide the KVM signature; the guest then also stops using kvm-clock.
    pub hide_kvm: bool,
    /// Expose performance counters, which real CPUs have.
    pub pmu: bool,
    /// One socket with N cores instead of one socket per CPU.
    pub realistic_topology: bool,
    /// The host's cache sizes instead of QEMU's made-up ones; passthrough only.
    pub host_cache_info: bool,
    pub nic: NicModel,
    /// Empty: QEMU's default 52:54:00:12:34:56.
    pub mac: String,
    /// VMware's I/O backdoor port, a VMware giveaway.
    pub vmport: bool,
    pub hpet: bool,
    /// Intel ICH9 USB controllers (EHCI with UHCI companions), as on a PC.
    pub usb: bool,
    pub rtc_localtime: bool,
}

impl Default for StealthProfile {
    fn default() -> Self {
        Self::transparent()
    }
}

/// A real machine whose firmware strings a preset copies.
pub struct MachineProfile {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: StealthPreset,
    /// `GenuineIntel`, `AuthenticAMD`: presets pick a machine that matches
    /// the host CPU, which passthrough shows to the guest.
    pub cpu_vendor: &'static str,
    bios: (&'static str, &'static str, &'static str),
    system: (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    ),
    board: (&'static str, &'static str),
    chassis_type: u8,
    acpi: (&'static str, &'static str),
    serial: SerialStyle,
}

#[derive(Clone, Copy)]
enum SerialStyle {
    /// Dell service tag: 7 characters.
    Dell,
    /// HP: country code and 7 more, 10 characters.
    Hp,
    /// Lenovo: 8 characters.
    Lenovo,
    /// Supermicro: a letter and 11 more.
    Supermicro,
}

pub const MACHINES: &[MachineProfile] = &[
    MachineProfile {
        id: "dell-optiplex-7090",
        label: "Dell OptiPlex 7090",
        kind: StealthPreset::RealisticDesktop,
        cpu_vendor: "GenuineIntel",
        bios: ("Dell Inc.", "1.21.0", "08/14/2024"),
        system: ("Dell Inc.", "OptiPlex 7090", "", "OptiPlex", "0A61"),
        board: ("Dell Inc.", "0K0J0Y"),
        chassis_type: 3,
        acpi: ("DELL  ", "CBX3    "),
        serial: SerialStyle::Dell,
    },
    MachineProfile {
        id: "hp-elitedesk-800-g6",
        label: "HP EliteDesk 800 G6",
        kind: StealthPreset::RealisticDesktop,
        cpu_vendor: "GenuineIntel",
        bios: ("HP", "S21 Ver. 02.15.00", "04/09/2024"),
        system: (
            "HP",
            "HP EliteDesk 800 G6 Desktop Mini PC",
            "",
            "103C_53307F HP EliteDesk",
            "1D2F0EA#ABA",
        ),
        board: ("HP", "8715"),
        chassis_type: 35,
        acpi: ("HPQOEM", "SLIC-BPC"),
        serial: SerialStyle::Hp,
    },
    MachineProfile {
        id: "lenovo-m75q-gen2",
        label: "Lenovo ThinkCentre M75q Gen 2",
        kind: StealthPreset::RealisticDesktop,
        cpu_vendor: "AuthenticAMD",
        bios: ("LENOVO", "M3DKT3AA", "03/12/2024"),
        system: (
            "LENOVO",
            "11JN0047US",
            "ThinkCentre M75q Gen 2",
            "ThinkCentre M75q Gen 2",
            "LENOVO_MT_11JN_BU_Think_FM_ThinkCentre M75q Gen 2",
        ),
        board: ("LENOVO", "3179"),
        chassis_type: 35,
        acpi: ("LENOVO", "TC-M3D  "),
        serial: SerialStyle::Lenovo,
    },
    MachineProfile {
        id: "hp-elitedesk-805-g8",
        label: "HP EliteDesk 805 G8",
        kind: StealthPreset::RealisticDesktop,
        cpu_vendor: "AuthenticAMD",
        bios: ("HP", "T21 Ver. 02.12.00", "02/20/2024"),
        system: (
            "HP",
            "HP EliteDesk 805 G8 Small Form Factor PC",
            "",
            "103C_53307F HP EliteDesk",
            "4B4M5UT#ABA",
        ),
        board: ("HP", "8770"),
        chassis_type: 3,
        acpi: ("HPQOEM", "SLIC-BPC"),
        serial: SerialStyle::Hp,
    },
    MachineProfile {
        id: "dell-latitude-5420",
        label: "Dell Latitude 5420",
        kind: StealthPreset::RealisticLaptop,
        cpu_vendor: "GenuineIntel",
        bios: ("Dell Inc.", "1.36.0", "06/12/2024"),
        system: ("Dell Inc.", "Latitude 5420", "", "Latitude", "0A20"),
        board: ("Dell Inc.", "0K6G8R"),
        chassis_type: 10,
        acpi: ("DELL  ", "CBX3    "),
        serial: SerialStyle::Dell,
    },
    MachineProfile {
        id: "lenovo-t14-gen3-amd",
        label: "Lenovo ThinkPad T14 Gen 3 (AMD)",
        kind: StealthPreset::RealisticLaptop,
        cpu_vendor: "AuthenticAMD",
        bios: ("LENOVO", "R23ET70W (1.40 )", "05/10/2024"),
        system: (
            "LENOVO",
            "21CF000FUS",
            "ThinkPad T14 Gen 3",
            "ThinkPad T14 Gen 3",
            "LENOVO_MT_21CF_BU_Think_FM_ThinkPad T14 Gen 3",
        ),
        board: ("LENOVO", "21CF000FUS"),
        chassis_type: 10,
        acpi: ("LENOVO", "TP-R23  "),
        serial: SerialStyle::Lenovo,
    },
    MachineProfile {
        id: "supermicro-x12sth",
        label: "Supermicro SYS-510T (X12STH-F)",
        kind: StealthPreset::RealisticServer,
        cpu_vendor: "GenuineIntel",
        bios: (
            "American Megatrends International, LLC.",
            "2.1",
            "02/21/2024",
        ),
        system: (
            "Supermicro",
            "SYS-510T-MR",
            "0123456789",
            "Default string",
            "Default string",
        ),
        board: ("Supermicro", "X12STH-F"),
        chassis_type: 23,
        acpi: ("SUPERM", "SMCI--MB"),
        serial: SerialStyle::Supermicro,
    },
    MachineProfile {
        id: "supermicro-h12ssl",
        label: "Supermicro AS-1014S (H12SSL-i)",
        kind: StealthPreset::RealisticServer,
        cpu_vendor: "AuthenticAMD",
        bios: ("American Megatrends Inc.", "2.6", "01/16/2024"),
        system: (
            "Supermicro",
            "AS -1014S-WTRT",
            "0123456789",
            "Default string",
            "Default string",
        ),
        board: ("Supermicro", "H12SSL-i"),
        chassis_type: 23,
        acpi: ("SUPERM", "SMCI--MB"),
        serial: SerialStyle::Supermicro,
    },
];

/// Random bytes from the same source as other identifiers.
fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count);
    while bytes.len() < count {
        let id = unique_id();
        bytes.extend(
            (0..id.len() / 2)
                .filter_map(|i| u8::from_str_radix(id.get(i * 2..i * 2 + 2)?, 16).ok()),
        );
    }
    bytes.truncate(count);
    bytes
}

fn random_text(alphabet: &[u8], len: usize) -> String {
    random_bytes(len)
        .into_iter()
        .map(|byte| alphabet[byte as usize % alphabet.len()] as char)
        .collect()
}

const UPPER_DIGITS: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

fn serial(style: SerialStyle) -> String {
    match style {
        SerialStyle::Dell => random_text(UPPER_DIGITS, 7),
        SerialStyle::Hp => {
            let countries = ["CZC", "MXL", "2UA", "8CG"];
            let pick = random_bytes(1)[0] as usize % countries.len();
            format!("{}{}", countries[pick], random_text(UPPER_DIGITS, 7))
        }
        SerialStyle::Lenovo => format!(
            "{}{}",
            random_text(b"MPRS", 1),
            random_text(UPPER_DIGITS, 7)
        ),
        SerialStyle::Supermicro => {
            format!("{}{}", random_text(b"ABCSZ", 1), random_text(DIGITS, 11))
        }
    }
}

/// A random version 4 UUID.
fn uuid() -> String {
    let mut bytes = random_bytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// A random address with `prefix`, the vendor part a real card would carry.
pub fn random_mac(prefix: [u8; 3]) -> String {
    let tail = random_bytes(3);
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        prefix[0], prefix[1], prefix[2], tail[0], tail[1], tail[2]
    )
}

/// SMBIOS chassis types a profile offers, with their names.
pub const CHASSIS: &[(u8, &str)] = &[
    (3, "Desktop"),
    (7, "Tower"),
    (35, "Mini PC"),
    (9, "Laptop"),
    (10, "Notebook"),
    (23, "Rack mount chassis"),
];

pub fn chassis_label(kind: u8) -> &'static str {
    CHASSIS
        .iter()
        .find(|(known, _)| *known == kind)
        .map_or("Other", |(_, label)| label)
}

/// The host CPU's vendor ID, as passthrough shows it to the guest.
pub fn host_cpu_vendor() -> String {
    host_cpuinfo("vendor_id").unwrap_or_default()
}

fn host_cpuinfo(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_owned())
    })
}

impl MachineIdentity {
    /// The firmware strings of `machine`, with new random serials.
    pub fn from_machine(machine: &MachineProfile) -> Self {
        let system_serial = serial(machine.serial);
        Self {
            profile: machine.id.into(),
            bios_vendor: machine.bios.0.into(),
            bios_version: machine.bios.1.into(),
            bios_date: machine.bios.2.into(),
            system_manufacturer: machine.system.0.into(),
            system_product: machine.system.1.into(),
            system_version: machine.system.2.into(),
            system_family: machine.system.3.into(),
            system_sku: machine.system.4.into(),
            board_manufacturer: machine.board.0.into(),
            board_product: machine.board.1.into(),
            board_serial: format!("/{system_serial}/{}/", random_text(UPPER_DIGITS, 14)),
            chassis_type: machine.chassis_type,
            chassis_serial: system_serial.clone(),
            system_serial,
            system_uuid: uuid(),
            memory_manufacturer: "Samsung".into(),
            memory_part: "M471A1K43DB1-CWE".into(),
            memory_serial: random_text(b"0123456789ABCDEF", 8),
            acpi_oem_id: machine.acpi.0.into(),
            acpi_table_id: machine.acpi.1.into(),
            cdrom_model: "HL-DT-ST DVD+-RW GU90N".into(),
            disk_serial: format!("S6PXNF0T{}", random_text(UPPER_DIGITS, 6)),
        }
    }

    /// New random serials, UUID and disk serial; the strings stay.
    pub fn rerandomize(&mut self) {
        let style = MACHINES
            .iter()
            .find(|machine| machine.id == self.profile)
            .map_or(SerialStyle::Dell, |machine| machine.serial);
        self.system_serial = serial(style);
        self.chassis_serial = self.system_serial.clone();
        self.board_serial = format!("/{}/{}/", self.system_serial, random_text(UPPER_DIGITS, 14));
        self.system_uuid = uuid();
        self.memory_serial = random_text(b"0123456789ABCDEF", 8);
        self.disk_serial = format!("S6PXNF0T{}", random_text(UPPER_DIGITS, 6));
    }
}

impl StealthProfile {
    /// QEMU's own identity, as Antinomie launched VMs before profiles.
    pub fn transparent() -> Self {
        Self {
            preset: StealthPreset::Transparent,
            identity_enabled: false,
            identity: MachineIdentity::default(),
            cpu_passthrough: false,
            hide_hypervisor: false,
            hide_kvm: false,
            pmu: false,
            realistic_topology: false,
            host_cache_info: false,
            nic: NicModel::VirtioNet,
            mac: String::new(),
            vmport: true,
            hpet: true,
            usb: false,
            rtc_localtime: false,
        }
    }

    /// A realistic `kind` (desktop, laptop or server) for a host whose CPU
    /// vendor is `cpu_vendor`, with new random serials and MAC address.
    pub fn realistic(kind: StealthPreset, cpu_vendor: &str) -> Self {
        let machine = MACHINES
            .iter()
            .find(|machine| machine.kind == kind && machine.cpu_vendor == cpu_vendor)
            .or_else(|| MACHINES.iter().find(|machine| machine.kind == kind))
            .unwrap_or(&MACHINES[0]);
        let nic = NicModel::E1000e;
        Self {
            preset: kind,
            identity_enabled: true,
            identity: MachineIdentity::from_machine(machine),
            cpu_passthrough: true,
            hide_hypervisor: true,
            hide_kvm: true,
            pmu: true,
            realistic_topology: true,
            host_cache_info: true,
            nic,
            mac: random_mac(nic.mac_prefix()),
            vmport: false,
            hpet: true,
            usb: true,
            rtc_localtime: false,
        }
    }

    /// The profile for `preset`; Custom keeps the current entries.
    pub fn for_preset(&self, preset: StealthPreset, cpu_vendor: &str) -> Self {
        match preset {
            StealthPreset::Transparent => Self::transparent(),
            StealthPreset::Custom => Self {
                preset,
                ..self.clone()
            },
            kind => Self::realistic(kind, cpu_vendor),
        }
    }

    /// Switch to `machine`'s firmware strings with new serials.
    pub fn use_machine(&mut self, machine: &MachineProfile) {
        self.identity = MachineIdentity::from_machine(machine);
        self.identity_enabled = true;
    }

    /// A new random MAC address with the network card's vendor prefix.
    pub fn new_mac(&mut self) {
        self.mac = random_mac(self.nic.mac_prefix());
    }

    /// A new random locally administered MAC address (no vendor prefix).
    pub fn new_local_mac(&mut self) {
        let head = random_bytes(3);
        self.mac = random_mac([(head[0] & 0xfc) | 0x02, head[1], head[2]]);
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.mac.is_empty() {
            let parts: Vec<_> = self.mac.split(':').collect();
            let valid = parts.len() == 6
                && parts
                    .iter()
                    .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok());
            if !valid {
                return Err(format!("MAC address {:?} is not six hex pairs", self.mac));
            }
            if u8::from_str_radix(parts[0], 16).is_ok_and(|first| first & 1 == 1) {
                return Err("MAC address must not be a multicast address".into());
            }
        }
        let identity = &self.identity;
        if self.identity_enabled {
            if identity.acpi_oem_id.len() > 6 || identity.acpi_table_id.len() > 8 {
                return Err("ACPI OEM ID is at most 6 bytes and the table ID at most 8".into());
            }
            for text in [
                &identity.bios_vendor,
                &identity.bios_version,
                &identity.bios_date,
                &identity.system_manufacturer,
                &identity.system_product,
                &identity.system_version,
                &identity.system_family,
                &identity.system_sku,
                &identity.system_serial,
                &identity.board_manufacturer,
                &identity.board_product,
                &identity.board_serial,
                &identity.chassis_serial,
                &identity.memory_manufacturer,
                &identity.memory_part,
                &identity.memory_serial,
                &identity.acpi_oem_id,
                &identity.acpi_table_id,
                &identity.cdrom_model,
                &identity.disk_serial,
            ] {
                if text.chars().any(|c| c.is_control()) || text.len() > 64 {
                    return Err(format!(
                        "{text:?} has control characters or is longer than 64"
                    ));
                }
            }
            let uuid = &identity.system_uuid;
            let groups: Vec<_> = uuid.split('-').map(str::len).collect();
            if !uuid.is_empty()
                && (groups != [8, 4, 4, 4, 12]
                    || !uuid.chars().all(|c| c == '-' || c.is_ascii_hexdigit()))
            {
                return Err(format!("UUID {uuid:?} is not in 8-4-4-4-12 hex form"));
            }
        }
        Ok(())
    }

    /// What still tells a VM apart, most telling first.
    pub fn giveaways(&self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if !self.hide_hypervisor {
            found.push("CPUID hypervisor flag");
        }
        if !self.hide_kvm {
            found.push("KVM CPUID signature and kvm-clock");
        }
        if !self.identity_enabled {
            found.push("QEMU in the SMBIOS and ACPI tables, chassis type Other");
        }
        if !self.cpu_passthrough {
            found.push("QEMU CPU model name");
        }
        if self.mac.is_empty() {
            found.push("QEMU's MAC address 52:54:00:12:34:56");
        }
        if self.nic == NicModel::VirtioNet {
            found.push("virtio network card (Red Hat vendor ID)");
        }
        if self.vmport {
            found.push("VMware backdoor port");
        }
        if !self.usb {
            found.push("no USB controller");
        }
        if !self.pmu {
            found.push("no performance counters");
        }
        // Not covered by any entry: needed by Antinomie or outside QEMU options.
        found.extend([
            "virtio disk and display (Red Hat vendor ID)",
            "QEMU fw_cfg device and q35 chipset layout",
            "Antinomie options on the guest kernel command line",
            "timing of VM exits",
        ]);
        found
    }

    /// How common checks (systemd-detect-virt, DMI strings, the CPUID
    /// hypervisor bit, MAC prefixes) would rate this VM.
    pub fn rating(&self) -> &'static str {
        if !self.hide_hypervisor || !self.hide_kvm || !self.identity_enabled {
            "certain"
        } else if self.mac.is_empty() || !self.cpu_passthrough || self.nic == NicModel::VirtioNet {
            "possible"
        } else {
            "unlikely"
        }
    }
}

/// QEMU option values double their commas.
fn escape(text: &str) -> String {
    text.replace(',', ",,")
}

/// Extra `-machine` properties.
pub(crate) fn machine_options(profile: &StealthProfile) -> String {
    // Only what differs from QEMU's defaults, so Transparent launches as before.
    let mut options = String::new();
    if !profile.vmport {
        options.push_str(",vmport=off");
    }
    if !profile.hpet {
        options.push_str(",hpet=off");
    }
    if profile.usb {
        // q35 then adds ICH9 EHCI with its UHCI companions at 00:1d.
        options.push_str(",usb=on");
    }
    if profile.identity_enabled {
        options.push_str(",smbios-entry-point-type=64");
        let identity = &profile.identity;
        if !identity.acpi_oem_id.is_empty() {
            options.push_str(&format!(",x-oem-id={}", escape(&identity.acpi_oem_id)));
        }
        if !identity.acpi_table_id.is_empty() {
            options.push_str(&format!(
                ",x-oem-table-id={}",
                escape(&identity.acpi_table_id)
            ));
        }
    }
    options
}

/// The `-cpu` value: `base` (from the VM's CPU model setting) with the
/// profile's CPU entries. Passthrough needs KVM.
pub(crate) fn cpu_option(
    profile: &StealthProfile,
    base: Option<&str>,
    kvm: bool,
) -> Option<String> {
    let mut model = if profile.cpu_passthrough && kvm {
        "host".to_owned()
    } else if profile.cpu_passthrough {
        // Without KVM the host CPU cannot be passed through; show its name.
        let brand = host_cpuinfo("model name")
            .unwrap_or_else(|| "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz".into());
        format!("max,model-id={}", escape(&brand))
    } else {
        base?.to_owned()
    };
    if model.is_empty() {
        return None;
    }
    if profile.host_cache_info && model == "host" {
        model.push_str(",host-cache-info=on");
    }
    if profile.hide_hypervisor {
        model.push_str(",-hypervisor");
    }
    if profile.hide_kvm && kvm {
        model.push_str(",kvm=off");
    }
    if profile.pmu && kvm {
        model.push_str(",pmu=on");
    }
    Some(model)
}

/// The `-smp` value.
pub(crate) fn smp_option(profile: &StealthProfile, cpus: u16) -> String {
    if profile.realistic_topology {
        format!("{cpus},sockets=1,cores={cpus},threads=1")
    } else {
        cpus.to_string()
    }
}

/// The network card `-device` value for netdev `net0`.
pub(crate) fn nic_option(profile: &StealthProfile) -> String {
    let mut device = format!("{},netdev=net0", profile.nic.device());
    if !profile.mac.is_empty() {
        device.push_str(&format!(",mac={}", profile.mac));
    }
    device
}

/// SMBIOS, device identity and clock options; the chassis table is written
/// into `runtime_dir`.
pub(crate) fn apply(
    command: &mut Command,
    profile: &StealthProfile,
    runtime_dir: &Path,
) -> Result<(), String> {
    profile.validate()?;
    if profile.rtc_localtime {
        command.args(["-rtc", "base=localtime"]);
    }
    if !profile.identity_enabled {
        return Ok(());
    }
    let id = &profile.identity;
    let field = |name: &str, value: &str| {
        if value.is_empty() {
            String::new()
        } else {
            format!(",{name}={}", escape(value))
        }
    };
    let release = id
        .bios_version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .take(2)
        .collect::<Vec<_>>();
    let release = match release.as_slice() {
        [major, minor, ..] => format!(
            ",release={}.{}",
            major.parse::<u8>().unwrap_or(1),
            minor.parse::<u8>().unwrap_or(0)
        ),
        _ => String::new(),
    };
    command.arg("-smbios").arg(format!(
        "type=0{}{}{}{release}",
        field("vendor", &id.bios_vendor),
        field("version", &id.bios_version),
        field("date", &id.bios_date)
    ));
    command.arg("-smbios").arg(format!(
        "type=1{}{}{}{}{}{}{}",
        field("manufacturer", &id.system_manufacturer),
        field("product", &id.system_product),
        field("version", &id.system_version),
        field("serial", &id.system_serial),
        field("uuid", &id.system_uuid),
        field("sku", &id.system_sku),
        field("family", &id.system_family)
    ));
    command.arg("-smbios").arg(format!(
        "type=2{}{}{}",
        field("manufacturer", &id.board_manufacturer),
        field("product", &id.board_product),
        field("serial", &id.board_serial)
    ));
    let (cpu_vendor, cpu_name) = (
        host_cpu_vendor(),
        host_cpuinfo("model name").unwrap_or_default(),
    );
    let cpu_maker = match cpu_vendor.as_str() {
        "GenuineIntel" => "Intel(R) Corporation",
        "AuthenticAMD" => "Advanced Micro Devices, Inc.",
        _ => "",
    };
    command.arg("-smbios").arg(format!(
        "type=4{}{}",
        field("manufacturer", cpu_maker),
        field("version", &cpu_name)
    ));
    command.arg("-smbios").arg(format!(
        "type=17{}{}{},speed=3200",
        field("manufacturer", &id.memory_manufacturer),
        field("part", &id.memory_part),
        field("serial", &id.memory_serial)
    ));
    // QEMU's type 3 options cannot set the chassis type, so the table is
    // written whole and loaded in place of the generated one.
    let chassis = runtime_dir.join("smbios-chassis.bin");
    std::fs::write(&chassis, chassis_table(id))
        .map_err(|error| format!("SMBIOS chassis table: {error}"))?;
    command
        .arg("-smbios")
        .arg(format!("file={}", escape(&chassis.to_string_lossy())));
    if !id.disk_serial.is_empty() {
        command
            .arg("-global")
            .arg(format!("virtio-blk-pci.serial={}", escape(&id.disk_serial)));
    }
    if !id.cdrom_model.is_empty() {
        command
            .arg("-global")
            .arg(format!("ide-cd.model={}", escape(&id.cdrom_model)));
    }
    Ok(())
}

/// An SMBIOS type 3 (chassis) structure with its strings.
fn chassis_table(id: &MachineIdentity) -> Vec<u8> {
    let manufacturer = if id.system_manufacturer.is_empty() {
        "Default string"
    } else {
        &id.system_manufacturer
    };
    let serial = if id.chassis_serial.is_empty() {
        "Default string"
    } else {
        &id.chassis_serial
    };
    let strings = [
        manufacturer,
        "Not Specified",
        serial,
        "Not Specified",
        "Default string",
    ];
    let mut table = vec![
        3,    // type: system enclosure or chassis
        0x16, // length of the formatted area
        0x00,
        0x03, // handle
        1,    // manufacturer: string 1
        id.chassis_type.max(1),
        2, // version
        3, // serial number
        4, // asset tag
        3,
        3,
        3, // boot-up, power supply and thermal state: safe
        3, // security status: none
        0,
        0,
        0,
        0, // OEM defined
        0, // height
        1, // power cords
        0,
        0, // no contained elements
        5, // SKU number
    ];
    for text in strings {
        table.extend(text.bytes().filter(|byte| *byte != 0));
        table.push(0);
    }
    table.push(0);
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_fill_a_realistic_identity_matching_the_host_cpu() {
        let amd = StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD");
        assert_eq!(amd.identity.profile, "lenovo-m75q-gen2");
        let intel = StealthProfile::realistic(StealthPreset::RealisticLaptop, "GenuineIntel");
        assert_eq!(intel.identity.profile, "dell-latitude-5420");
        assert_eq!(intel.identity.chassis_type, 10);
        let server = StealthProfile::realistic(StealthPreset::RealisticServer, "unknown");
        assert_eq!(server.identity.chassis_type, 23);
        for profile in [&amd, &intel, &server] {
            profile.validate().unwrap();
            assert!(profile.mac.starts_with("3c:fd:fe:"));
            assert_eq!(profile.rating(), "unlikely");
            assert_eq!(profile.identity.system_uuid.len(), 36);
        }
        // Two VMs never share their serials or MAC address.
        assert_ne!(
            amd.identity.system_serial,
            StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD")
                .identity
                .system_serial
        );
        assert_ne!(
            amd.mac,
            StealthProfile::realistic(StealthPreset::RealisticDesktop, "AuthenticAMD").mac
        );
    }

    #[test]
    fn transparent_keeps_qemu_launch_options_and_rates_certain() {
        let profile = StealthProfile::transparent();
        assert_eq!(profile.rating(), "certain");
        assert_eq!(smp_option(&profile, 4), "4");
        assert_eq!(nic_option(&profile), "virtio-net-pci,netdev=net0");
        assert_eq!(cpu_option(&profile, None, true), None);
        assert_eq!(
            cpu_option(&profile, Some("max"), true).as_deref(),
            Some("max")
        );
        assert_eq!(machine_options(&profile), "");
        // Old saved configurations have no profile and stay transparent.
        let old: StealthProfile = serde_json::from_str("{}").unwrap();
        assert_eq!(old, StealthProfile::transparent());
    }

    #[test]
    fn realistic_options_hide_the_hypervisor_and_carry_the_identity() {
        let profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
        assert_eq!(
            cpu_option(&profile, None, true).as_deref(),
            Some("host,host-cache-info=on,-hypervisor,kvm=off,pmu=on")
        );
        assert!(
            cpu_option(&profile, None, false)
                .unwrap()
                .starts_with("max,model-id=")
        );
        assert_eq!(smp_option(&profile, 4), "4,sockets=1,cores=4,threads=1");
        assert!(nic_option(&profile).starts_with("e1000e,netdev=net0,mac=3c:fd:fe:"));
        let machine = machine_options(&profile);
        assert!(machine.contains(",vmport=off"));
        assert!(machine.contains(",usb=on"));
        assert!(machine.contains(",x-oem-id=DELL  "));
        let mut local = profile.clone();
        local.new_local_mac();
        let first = u8::from_str_radix(&local.mac[..2], 16).unwrap();
        assert_eq!(first & 3, 2, "{}", local.mac);
        assert!(local.validate().is_ok());
        let dir = std::env::temp_dir().join(format!("ant-stealth-{}", unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut command = Command::new("qemu");
        apply(&mut command, &profile, &dir).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("type=1,manufacturer=Dell Inc.,product=OptiPlex 7090"))
        );
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("virtio-blk-pci.serial=S6PXNF0T"))
        );
        let chassis = std::fs::read(dir.join("smbios-chassis.bin")).unwrap();
        assert_eq!(&chassis[..6], &[3, 0x16, 0, 3, 1, 3]);
        assert!(chassis.ends_with(b"Default string\0\0"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn commas_are_escaped_and_bad_addresses_are_refused() {
        let mut profile = StealthProfile::realistic(StealthPreset::RealisticServer, "AuthenticAMD");
        assert!(machine_options(&profile).contains("x-oem-id=SUPERM"));
        let dir = std::env::temp_dir().join(format!("ant-stealth-{}", unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut command = Command::new("qemu");
        apply(&mut command, &profile, &dir).unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter()
                .any(|arg| arg.contains("vendor=American Megatrends Inc."))
        );
        std::fs::remove_dir_all(dir).unwrap();
        profile.identity.bios_vendor = "Vendor, Inc.".into();
        assert_eq!(escape(&profile.identity.bios_vendor), "Vendor,, Inc.");
        profile.mac = "01:00:00:00:00:01".into();
        assert!(profile.validate().is_err());
        profile.mac = "zz".into();
        assert!(profile.validate().is_err());
        profile.mac.clear();
        profile.identity.system_uuid = "not-a-uuid".into();
        assert!(profile.validate().unwrap_err().contains("UUID"));
        profile.identity.system_uuid = uuid();
        profile.identity.memory_part = "line\nbreak".into();
        assert!(profile.validate().is_err());
    }
}
