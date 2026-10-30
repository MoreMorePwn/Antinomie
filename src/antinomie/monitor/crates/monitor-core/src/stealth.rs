// SPDX-License-Identifier: GPL-3.0-only
//! Device profile: QEMU launch options that make a VM look like ordinary
//! hardware to software that checks whether it runs in a VM.
//!
//! The profile is stored per VM. A preset fills every entry; serials, the
//! system UUID and the MAC address are random per VM and kept, so one VM keeps
//! its identity across boots and two VMs never share one. Everything here is
//! a launch option. The guest kernel keeps its own traces out of the guest
//! (its boot options, build string, symbols, worker names and QEMU's ACPI
//! devices); what neither can change is listed by `giveaways()`.
//!
//! Some entries need the base (UEFI, a SATA or NVMe root disk, a guest network
//! of its own) or the host (OVMF, two threads per core); `fitted()` turns an
//! entry the base or host lacks back into the choice every one has.
use crate::storage::unique_id;
pub use catalog::{MACHINES, MachineProfile, NicFit, Variant};
use catalog::{SerialStyle, SmbiosFields, Subsystem};
pub use cloud::{CLOUDS, CloudProvider, MachineType, MetadataStyle, Owner, Plan, StateFile};
pub use cpu::{CpuGen, HostCpu, classify};
use parts::{DiskModel, RamPart};
pub use record::MachineRecord;
use serde::{Deserialize, Serialize};

mod catalog;
mod cloud;
#[cfg(test)]
mod cloud_tests;
mod cpu;
mod firmware;
mod launch;
mod memory;
mod nat;
mod parts;
mod processor;
mod record;
mod smbios;
#[cfg(test)]
mod tests;

pub use firmware::{Ovmf, find_ovmf};
pub(crate) use launch::{
    apply, cpu_option, disk_args, escape, firmware_args, machine_options, netdev_option,
    nic_option_for, pointer_args, smp_option,
};
pub use nat::NatNetwork;

/// A starting point for every entry; changing one makes the profile Custom.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum StealthPreset {
    RealisticDesktop,
    RealisticLaptop,
    RealisticServer,
    /// An instance of a KVM cloud (Tencent, Alibaba, DigitalOcean, Vultr):
    /// the hypervisor stays visible, as on the provider's machines.
    CloudVps,
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
        Self::CloudVps,
        Self::Transparent,
        Self::Custom,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::RealisticDesktop => "Realistic desktop",
            Self::RealisticLaptop => "Realistic laptop",
            Self::RealisticServer => "Realistic server",
            Self::CloudVps => "Cloud VPS",
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

/// Where the network card sits on PCI bus 0 for a base that names its NIC by
/// that place (stealth support `onboardnic`): the integrated LAN of the
/// chipset the profile's machine has. udev names the interface from the slot
/// whatever the card's model, and the slot stays the same whichever display
/// or pointer devices take the first free slots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NicSlot {
    /// 00:19.0 (`enp0s25`): the integrated Intel LAN of the ICH8 to 9 series
    /// chipsets (82566 to I218), among them the ICH9 QEMU's q35 copies. The
    /// place for a profile with no machine identity, or one with an AMD
    /// chipset, which has no integrated LAN on bus 0.
    #[default]
    Ich,
    /// 00:1f.6 (`enp0s31f6`): the integrated Intel LAN (I219) of the 100
    /// series and later chipsets, beside the LPC bridge at 00:1f.0.
    Pch,
    /// 00:19.0 with ACPI index 1 (`eno1`): a board whose LAN is not the
    /// chipset's I219 but a controller on the board, which firmware names
    /// by index (the Supermicro servers' Intel I210 or Broadcom ports).
    /// QEMU's `acpi-index` puts that index in the DSDT, and Debian's udev
    /// names the interface from it instead of from the slot.
    Eno1,
    /// 00:03.0 (`ens3`): the first free slot of an i440FX machine, after
    /// the host bridge, PIIX3 and the display, where a cloud's virtio card
    /// sits.
    Pc,
}

impl NicSlot {
    pub const ALL: [Self; 4] = [Self::Ich, Self::Pch, Self::Eno1, Self::Pc];

    /// The PCI address, as a `-device` option.
    pub fn address(self) -> &'static str {
        match self {
            Self::Ich => "addr=0x19",
            Self::Pch => "addr=0x1f.0x6",
            Self::Eno1 => "addr=0x19,acpi-index=1",
            Self::Pc => "addr=0x3",
        }
    }

    /// The name udev's predictable naming gives the interface there.
    pub fn interface(self) -> &'static str {
        match self {
            Self::Ich => "enp0s25",
            Self::Pch => "enp0s31f6",
            Self::Eno1 => "eno1",
            Self::Pc => "ens3",
        }
    }

    /// The slot whose interface is `name`, if it is one of these.
    pub fn from_interface(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|slot| slot.interface() == name)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ich => "PCI 00:19.0 (enp0s25)",
            Self::Pch => "PCI 00:1f.6 (enp0s31f6)",
            Self::Eno1 => "PCI 00:19.0, firmware index 1 (eno1)",
            Self::Pc => "PCI 00:03.0 (ens3)",
        }
    }
}

/// The machine's firmware.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Firmware {
    /// SeaBIOS, QEMU's default: no `/sys/firmware/efi` in the guest.
    #[default]
    Bios,
    /// OVMF with an empty variable store, Secure Boot off.
    Uefi,
    /// OVMF with Microsoft's keys enrolled: Secure Boot on (needs SMM).
    UefiSecureBoot,
}

impl Firmware {
    pub const ALL: &'static [Self] = &[Self::Bios, Self::Uefi, Self::UefiSecureBoot];

    pub fn label(self) -> &'static str {
        match self {
            Self::Bios => "BIOS (SeaBIOS)",
            Self::Uefi => "UEFI (OVMF)",
            Self::UefiSecureBoot => "UEFI with Secure Boot (OVMF, Microsoft keys)",
        }
    }

    pub fn is_uefi(self) -> bool {
        self != Self::Bios
    }
}

/// The bus of the root disk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskBus {
    /// Fastest; `vda` with Red Hat's vendor ID.
    #[default]
    Virtio,
    /// On q35's ICH9 AHCI controller: `sda`, vendor ATA, the model set here.
    Sata,
    /// QEMU's NVMe controller, whose model name says QEMU.
    Nvme,
}

impl DiskBus {
    pub const ALL: &'static [Self] = &[Self::Virtio, Self::Sata, Self::Nvme];

    pub fn label(self) -> &'static str {
        match self {
            Self::Virtio => "virtio (fastest, VM vendor ID)",
            Self::Sata => "SATA (AHCI)",
            Self::Nvme => "NVMe (model says QEMU)",
        }
    }
}

/// What the disk says it is: SATA reports its rotation rate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskMedia {
    #[default]
    Ssd,
    /// A spinning disk: 7,200 rpm, or the identity's disk's own speed.
    Hdd,
}

impl DiskMedia {
    /// The media of a disk that rotates at `rotation` (1 for an SSD, 0 for
    /// unknown).
    pub fn of_rotation(rotation: u16) -> Self {
        if rotation > 1 { Self::Hdd } else { Self::Ssd }
    }
}

/// The pointing device beside the display (the VM window only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pointer {
    /// Absolute, needs no driver beyond virtio-input.
    #[default]
    VirtioTablet,
    /// Absolute, on the ICH9 USB controllers.
    UsbTablet,
    /// The PS/2 mouse every q35 machine has, relative.
    Ps2,
}

impl Pointer {
    pub const ALL: &'static [Self] = &[Self::VirtioTablet, Self::UsbTablet, Self::Ps2];

    pub fn label(self) -> &'static str {
        match self {
            Self::VirtioTablet => "virtio tablet",
            Self::UsbTablet => "USB tablet",
            Self::Ps2 => "PS/2 mouse only",
        }
    }

    /// What the choice costs.
    pub fn cost(self) -> &'static str {
        match self {
            Self::VirtioTablet => {
                "The pointer follows the host's; a virtio device named \"QEMU Virtio Tablet\""
            }
            Self::UsbTablet => {
                "The pointer follows the host's; named \"QEMU USB Tablet\", needs the USB controllers"
            }
            Self::Ps2 => {
                "Looks like a PC's mouse; the window grabs the pointer on a click \
                 (Ctrl+Alt+G releases it)"
            }
        }
    }
}

/// The SMBIOS entry point: 32-bit (SMBIOS 2.x) or 64-bit (SMBIOS 3.x, as
/// current PCs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmbiosEntry {
    #[default]
    Bits64,
    Bits32,
}

/// What drives the emulated real-time clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RtcClock {
    /// The host's clock, QEMU's default: wall time goes on while the VM is
    /// paused.
    #[default]
    Host,
    /// The VM's own clock, which stops while the VM is paused.
    Vm,
}

/// A named QEMU CPU model with the brand string it shows, for a VM without
/// passthrough. The family and model numbers stay the QEMU model's.
pub struct CpuModel {
    pub model: &'static str,
    pub cpu_vendor: &'static str,
    pub brand: &'static str,
}

pub const CPU_MODELS: &[CpuModel] = &[
    CpuModel {
        model: "Skylake-Client-v4",
        cpu_vendor: "GenuineIntel",
        brand: "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz",
    },
    CpuModel {
        model: "Cascadelake-Server-v5",
        cpu_vendor: "GenuineIntel",
        brand: "Intel(R) Xeon(R) Silver 4210R CPU @ 2.40GHz",
    },
    CpuModel {
        model: "EPYC-Rome-v4",
        cpu_vendor: "AuthenticAMD",
        brand: "AMD Ryzen 5 3600 6-Core Processor",
    },
    CpuModel {
        model: "EPYC-Milan-v2",
        cpu_vendor: "AuthenticAMD",
        brand: "AMD Ryzen 7 5800X 8-Core Processor",
    },
];

/// What the firmware tables, the CPU and the devices say about the machine.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MachineIdentity {
    /// The built-in profile these values came from, or empty when edited.
    pub profile: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    /// SMBIOS type 0 "system is a virtual machine" bit: set by cloud
    /// firmware, never by a PC's.
    pub virtual_machine: bool,
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
    /// Base board version and location in chassis. These and the chassis,
    /// processor and memory slot entries below came in 0.8.0; an identity
    /// saved before has them empty and takes its machine's at launch
    /// ([`MachineIdentity::with_firmware_fields`]).
    pub board_version: String,
    pub board_location: String,
    /// SMBIOS chassis type: 3 desktop, 7 tower, 35 mini PC, 9 laptop,
    /// 10 notebook, 23 rack mount chassis.
    pub chassis_type: u8,
    pub chassis_serial: String,
    /// Chassis and processor maker and the processor's version string when
    /// the machine's are not the system maker's and the host CPU's (a cloud's
    /// QEMU); empty: derived.
    pub chassis_manufacturer: String,
    pub cpu_manufacturer: String,
    pub cpu_version: String,
    pub chassis_version: String,
    pub chassis_sku: String,
    /// Processor socket designation and part number.
    pub cpu_socket: String,
    pub cpu_part: String,
    /// Processor upgrade code and voltage in tenths of a volt (type 4); 0
    /// when not recorded.
    pub cpu_upgrade: u8,
    pub cpu_voltage: u8,
    pub memory_manufacturer: String,
    pub memory_part: String,
    pub memory_serial: String,
    /// The memory slots of the machine, the first one used first.
    pub memory_slots: Vec<MemorySlot>,
    /// SMBIOS memory form factor (9 DIMM, 13 SO-DIMM, 1 soldered) and type
    /// detail bits; 0 when not recorded.
    pub memory_form: u8,
    pub memory_detail: u16,
    /// The module's SMBIOS memory type (0x1a DDR4, 0x22 DDR5, 0x23 LPDDR5),
    /// speed in MT/s, rank and total width in bits (72 with ECC); 0 when not
    /// recorded (an identity saved before 0.8.0: DDR4-3200, rank 1, 64 bits).
    pub memory_type: u8,
    pub memory_speed: u16,
    pub memory_rank: u8,
    pub memory_width: u16,
    /// ACPI table header OEM ID (6 bytes) and OEM table ID (8 bytes).
    pub acpi_oem_id: String,
    pub acpi_table_id: String,
    pub cdrom_model: String,
    pub disk_serial: String,
    /// SATA model, firmware revision and world wide name (16 hex digits);
    /// NVMe takes the serial only.
    pub disk_model: String,
    pub disk_firmware: String,
    pub disk_wwn: String,
    /// The SATA disk's rotation rate: 1 for an SSD, else its spindle speed in
    /// rpm; 0 follows the profile's disk media setting.
    pub disk_rotation: u16,
    /// SMBIOS type 11 OEM strings.
    pub oem_strings: Vec<String>,
    /// PCI subsystem `vendor:device` of the network card (e1000e only), as a
    /// board's own card has its maker's; empty keeps Intel's.
    pub nic_subsystem: String,
}

/// A memory slot as the firmware names it: device and bank locator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemorySlot {
    pub locator: String,
    pub bank: String,
}

/// The device profile of one VM.
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
    pub firmware: Firmware,
    pub disk_bus: DiskBus,
    pub disk_media: DiskMedia,
    /// Two threads per core (with one socket of N/2 cores).
    pub smt: bool,
    pub pointer: Pointer,
    pub smbios_entry: SmbiosEntry,
    /// A named QEMU CPU model and brand string when not passing the host
    /// CPU through; empty: the VM's CPU model setting.
    pub cpu_model: String,
    pub cpu_brand: String,
    /// The named model's own cache layout instead of QEMU's legacy one.
    pub model_cache_info: bool,
    /// kvm-clock while the KVM signature is shown.
    pub kvm_clock: bool,
    pub smm: bool,
    pub rtc_clock: RtcClock,
    /// Slew the RTC's missed ticks back in (for guests that count them).
    pub rtc_driftfix: bool,
    /// An empty SATA CD-ROM drive, which QEMU names in its SCSI inquiry.
    pub cdrom: bool,
    /// The NAT's addresses; empty: QEMU's 10.0.2.0/24.
    pub nat: NatNetwork,
    /// The QEMU machine type (chipset).
    pub machine: MachineType,
    /// The cloud provider this profile is an instance of (a [`CLOUDS`] id),
    /// or empty.
    pub cloud: String,
}

impl Default for StealthProfile {
    fn default() -> Self {
        Self::transparent()
    }
}

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

pub(crate) fn random_text(alphabet: &[u8], len: usize) -> String {
    random_bytes(len)
        .into_iter()
        .map(|byte| alphabet[byte as usize % alphabet.len()] as char)
        .collect()
}

const UPPER_DIGITS: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";

/// The base board serial: Dell's is the service tag and a "CN" number between
/// slashes (14 characters, as in public dmidecode listings); no public source
/// shows the other makers' board serials, so they keep the same slashed form.
fn board_serial(style: SerialStyle, system_serial: &str) -> String {
    let number = match style {
        SerialStyle::Dell => format!("CN{}", random_text(UPPER_DIGITS, 12)),
        _ => random_text(UPPER_DIGITS, 14),
    };
    format!("/{system_serial}/{number}/")
}

fn serial(style: SerialStyle) -> String {
    match style {
        SerialStyle::Dell => random_text(UPPER_DIGITS, 7),
        SerialStyle::Hp => format!(
            "{}{}",
            pick(&["CZC", "MXL", "2UA", "8CG"]),
            random_text(UPPER_DIGITS, 7)
        ),
        SerialStyle::HpLaptop => format!(
            "{}{}",
            pick(&["5CG", "CND", "CNU", "8CG"]),
            random_text(UPPER_DIGITS, 7)
        ),
        SerialStyle::Lenovo => format!(
            "{}{}",
            random_text(b"MPRS", 1),
            random_text(UPPER_DIGITS, 7)
        ),
        SerialStyle::LenovoThinkPad => format!(
            "{}{}",
            pick(&["PF", "PG", "PC", "R9", "MP"]),
            random_text(UPPER_DIGITS, 6)
        ),
        SerialStyle::Supermicro => {
            format!("{}{}", random_text(b"ABCSZ", 1), random_text(DIGITS, 11))
        }
    }
}

/// A random number, for picking among alternatives.
fn roll() -> u32 {
    let bytes = random_bytes(4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// One of `items`, at random.
fn pick<T>(items: &[T]) -> &T {
    &items[roll() as usize % items.len()]
}

/// A random version 4 UUID.
pub(crate) fn uuid() -> String {
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
    (4, "Low profile desktop"),
    (7, "Tower"),
    (35, "Mini PC"),
    (9, "Laptop"),
    (10, "Notebook"),
    (17, "Main server chassis"),
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
    /// The firmware strings of `machine`: one real unit of the model, one of
    /// the BIOS releases it shipped with, one of the disks and memory modules
    /// seen in its units, and new random serials. Kept with the VM: nothing
    /// is picked again at boot.
    pub fn from_machine(machine: &MachineProfile) -> Self {
        let (bios, unit) = (pick(machine.bios), pick(machine.variants));
        let disk: &DiskModel = pick::<&DiskModel>(machine.disks);
        Self::build(machine, bios, unit, disk, pick(machine.memory))
    }

    /// The same for the first BIOS release, unit, disk and memory module
    /// listed: a fixed identity for tests and examples.
    pub fn first_listed(machine: &MachineProfile) -> Self {
        Self::build(
            machine,
            &machine.bios[0],
            &machine.variants[0],
            machine.disks[0],
            &machine.memory[0],
        )
    }

    fn build(
        machine: &MachineProfile,
        bios: &(&'static str, &'static str),
        unit: &Variant,
        disk: &DiskModel,
        ram: &RamPart,
    ) -> Self {
        let system_serial = serial(machine.serial);
        let fields = &machine.fields;
        let subsystem = match &machine.nic_subsystem {
            Subsystem::None => String::new(),
            Subsystem::Fixed(ids) => (*ids).into(),
            Subsystem::DellSku => format!("1028:{}", unit.sku.to_ascii_lowercase()),
            Subsystem::Board(vendor) => format!("{vendor}:{}", unit.board.to_ascii_lowercase()),
        };
        Self {
            profile: machine.id.into(),
            bios_vendor: machine.bios_vendor.into(),
            bios_version: bios.0.into(),
            bios_date: bios.1.into(),
            virtual_machine: false,
            chassis_manufacturer: String::new(),
            cpu_manufacturer: String::new(),
            cpu_version: String::new(),
            system_manufacturer: machine.manufacturer.into(),
            system_product: unit.product.into(),
            system_version: machine.version.into(),
            system_family: machine.family.into(),
            system_sku: unit.sku.into(),
            board_manufacturer: machine.board_manufacturer.into(),
            board_product: unit.board.into(),
            board_serial: board_serial(machine.serial, &system_serial),
            board_version: with_digits(pick(fields.board_versions), &random_text(DIGITS, 16)),
            board_location: fields.board_location.into(),
            chassis_type: unit.chassis,
            chassis_serial: system_serial.clone(),
            chassis_version: fields.chassis_version.into(),
            chassis_sku: fields.chassis_sku.into(),
            cpu_socket: fields.cpu_socket.into(),
            cpu_part: fields.cpu_part.into(),
            cpu_upgrade: fields.cpu_upgrade,
            cpu_voltage: fields.cpu_voltage,
            memory_slots: memory_slots(fields),
            memory_form: ram.form,
            memory_detail: fields.dimm_detail,
            memory_type: ram.memory_type,
            memory_speed: ram.speed,
            memory_rank: ram.rank,
            memory_width: ram.width,
            system_serial,
            system_uuid: uuid(),
            memory_manufacturer: ram.manufacturer.into(),
            memory_part: ram.part.into(),
            memory_serial: random_text(b"0123456789ABCDEF", 8),
            acpi_oem_id: machine.acpi.0.into(),
            acpi_table_id: machine.acpi.1.into(),
            cdrom_model: machine.cdrom_model.into(),
            disk_serial: disk_serial(disk),
            disk_model: disk.model.into(),
            disk_firmware: disk.firmware.into(),
            disk_wwn: disk_wwn(disk),
            disk_rotation: disk.rotation,
            oem_strings: machine
                .oem_strings
                .iter()
                .map(|text| text.replace("{sku}", unit.sku))
                .collect(),
            nic_subsystem: if launch::pci_ids(&subsystem).is_some() {
                subsystem
            } else {
                String::new()
            },
        }
    }

    /// This identity with the firmware fields an identity saved before 0.8.0
    /// lacks (board version and location, chassis version and SKU, processor
    /// socket and part, memory slots) taken from its machine, so a launch
    /// never leaves them to QEMU. A per-unit number in the board version
    /// follows from the system UUID, so it stays the same at every boot.
    pub fn with_firmware_fields(&self) -> Self {
        let mut identity = self.clone();
        let Some(machine) = MACHINES
            .iter()
            .find(|machine| machine.id == identity.profile)
        else {
            if identity.memory_slots.is_empty() {
                identity.memory_slots = vec![MemorySlot {
                    locator: "DIMM1".into(),
                    bank: String::new(),
                }];
            }
            if identity.memory_form == 0 {
                identity.memory_form = if matches!(identity.chassis_type, 8 | 9 | 10 | 14 | 31 | 32)
                {
                    13
                } else {
                    9
                };
            }
            if identity.memory_detail == 0 {
                identity.memory_detail = 0x0080;
            }
            return identity;
        };
        let fields = &machine.fields;
        let fill = |value: &mut String, from: &str| {
            if value.is_empty() {
                *value = from.into();
            }
        };
        let digits: String = identity
            .system_uuid
            .chars()
            .filter_map(|c| c.to_digit(16))
            .map(|value| char::from(b'0' + (value % 10) as u8))
            .collect();
        let board_version = with_digits(fields.board_versions[0], &digits);
        fill(&mut identity.board_version, &board_version);
        fill(&mut identity.board_location, fields.board_location);
        fill(&mut identity.chassis_version, fields.chassis_version);
        fill(&mut identity.chassis_sku, fields.chassis_sku);
        fill(&mut identity.cpu_socket, fields.cpu_socket);
        fill(&mut identity.cpu_part, fields.cpu_part);
        if identity.cpu_upgrade == 0 {
            (identity.cpu_upgrade, identity.cpu_voltage) = (fields.cpu_upgrade, fields.cpu_voltage);
        }
        if identity.memory_slots.is_empty() {
            identity.memory_slots = memory_slots(fields);
        }
        if identity.memory_form == 0 {
            identity.memory_form = machine.memory[0].form;
        }
        if identity.memory_detail == 0 {
            identity.memory_detail = fields.dimm_detail;
        }
        identity
    }

    /// New random serials, UUID and disk serial; the strings stay.
    pub fn rerandomize(&mut self) {
        if let Some(provider) = CloudProvider::find(&self.profile) {
            let fresh = provider.identity();
            self.system_serial = fresh.system_serial;
            self.chassis_serial = fresh.chassis_serial;
            self.board_serial = fresh.board_serial;
            self.system_uuid = fresh.system_uuid;
            return;
        }
        let machine = MACHINES.iter().find(|machine| machine.id == self.profile);
        if let Some(machine) = machine
            && machine
                .fields
                .board_versions
                .iter()
                .any(|version| version.contains('#'))
        {
            self.board_version = with_digits(
                pick(machine.fields.board_versions),
                &random_text(DIGITS, 16),
            );
        }
        let style = machine.map_or(SerialStyle::Dell, |machine| machine.serial);
        self.system_serial = serial(style);
        self.chassis_serial = self.system_serial.clone();
        self.board_serial = board_serial(style, &self.system_serial);
        self.system_uuid = uuid();
        self.memory_serial = random_text(b"0123456789ABCDEF", 8);
        let known = MACHINES
            .iter()
            .flat_map(|machine| machine.disks)
            .filter(|disk| disk.model == self.disk_model)
            .min_by_key(|disk| disk.firmware != self.disk_firmware);
        match known {
            Some(disk) => {
                self.disk_serial = disk_serial(disk);
                self.disk_wwn = disk_wwn(disk);
            }
            None => {
                // A disk the catalog no longer lists: the same length and
                // start, a new tail; the WWN keeps its maker's OUI.
                let count = self.disk_serial.chars().count();
                let head: String = self.disk_serial.chars().take(count / 2).collect();
                self.disk_serial =
                    format!("{head}{}", random_text(UPPER_DIGITS, count - count / 2));
                if self.disk_wwn.len() == 16 && self.disk_wwn.is_ascii() {
                    let oui = self.disk_wwn[..7].to_owned();
                    self.disk_wwn = format!("{oui}{}", random_text(b"0123456789abcdef", 9));
                }
            }
        }
    }
}

/// `template` with each `#` replaced by the next of `digits` (0 once they
/// run out).
fn with_digits(template: &str, digits: &str) -> String {
    let mut digits = digits.chars();
    template
        .chars()
        .map(|c| {
            if c == '#' {
                digits.next().unwrap_or('0')
            } else {
                c
            }
        })
        .collect()
}

/// The memory slots of `fields` as an identity keeps them.
fn memory_slots(fields: &SmbiosFields) -> Vec<MemorySlot> {
    fields
        .dimm_slots
        .iter()
        .map(|(locator, bank)| MemorySlot {
            locator: (*locator).into(),
            bank: (*bank).into(),
        })
        .collect()
}

/// A serial number as `disk`'s maker numbers them.
fn disk_serial(disk: &DiskModel) -> String {
    format!(
        "{}{}",
        disk.serial_prefix,
        random_text(disk.serial_alphabet, disk.serial_tail)
    )
}

/// A world wide name in `disk`'s maker's NAA 5 range: 5, the maker's OUI and
/// nine random hex digits, 16 hex digits; none for a disk without one.
fn disk_wwn(disk: &DiskModel) -> String {
    if disk.oui.is_empty() {
        return String::new();
    }
    format!("5{}{}", disk.oui, random_text(b"0123456789abcdef", 9))
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
            firmware: Firmware::Bios,
            disk_bus: DiskBus::Virtio,
            disk_media: DiskMedia::Ssd,
            smt: false,
            pointer: Pointer::VirtioTablet,
            smbios_entry: SmbiosEntry::Bits64,
            cpu_model: String::new(),
            cpu_brand: String::new(),
            model_cache_info: false,
            kvm_clock: true,
            smm: true,
            rtc_clock: RtcClock::Host,
            rtc_driftfix: false,
            cdrom: false,
            nat: NatNetwork::default(),
            machine: MachineType::Q35,
            cloud: String::new(),
        }
    }

    /// A realistic `kind` (desktop, laptop or server) for a host whose CPU
    /// vendor is `cpu_vendor`, with new random serials and MAC address. Use
    /// [`realistic_on`](Self::realistic_on) when the generation is known.
    pub fn realistic(kind: StealthPreset, cpu_vendor: &str) -> Self {
        Self::realistic_on(kind, &HostCpu::vendor_only(cpu_vendor))
    }

    /// A realistic `kind` of machine, picked at random (the likelier the more
    /// common the model) among those the host's CPU could be in, with new
    /// random serials and MAC address. The pick is saved with the VM: a boot
    /// never picks again.
    pub fn realistic_on(kind: StealthPreset, host: &HostCpu) -> Self {
        if kind == StealthPreset::CloudVps {
            return Self::cloud_vps(&CLOUDS[0]);
        }
        let (machine, _fits) = catalog::pick_machine(kind, host, roll());
        let nic = NicModel::E1000e;
        let identity = MachineIdentity::from_machine(machine);
        Self {
            preset: kind,
            identity_enabled: true,
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
            firmware: Firmware::Uefi,
            disk_bus: DiskBus::Sata,
            disk_media: DiskMedia::of_rotation(identity.disk_rotation),
            smt: true,
            pointer: Pointer::VirtioTablet,
            smbios_entry: SmbiosEntry::Bits64,
            cpu_model: String::new(),
            cpu_brand: String::new(),
            model_cache_info: false,
            kvm_clock: true,
            smm: true,
            rtc_clock: RtcClock::Host,
            rtc_driftfix: false,
            // QEMU names its CD-ROM drive in the SCSI inquiry; real ones
            // only come with the machines that have one, and cost that.
            cdrom: false,
            nat: NatNetwork::home(),
            identity,
            machine: MachineType::Q35,
            cloud: String::new(),
        }
    }

    /// A new instance of `provider`: its firmware strings, chipset, MAC
    /// prefix and DHCP network, with the hypervisor left visible (a hidden
    /// flag on a cloud's DMI strings would itself be odd).
    pub fn cloud_vps(provider: &CloudProvider) -> Self {
        let identity = provider.identity();
        let mut profile = Self {
            preset: StealthPreset::CloudVps,
            identity_enabled: true,
            cpu_passthrough: true,
            realistic_topology: true,
            smbios_entry: SmbiosEntry::Bits32,
            vmport: provider.vmport,
            cdrom: provider.cdrom,
            nat: provider.nat(),
            machine: provider.machine,
            cloud: provider.id.into(),
            identity,
            ..Self::transparent()
        };
        profile.preset = StealthPreset::CloudVps;
        profile.mac = match provider.mac_prefix {
            Some(prefix) => random_mac(prefix),
            None => {
                profile.new_local_mac();
                profile.mac.clone()
            }
        };
        profile
    }

    /// The cloud provider of this profile.
    pub fn cloud_provider(&self) -> Option<&'static CloudProvider> {
        CloudProvider::find(&self.cloud)
    }

    /// The profile for `preset`; Custom keeps the current entries.
    pub fn for_preset(&self, preset: StealthPreset, cpu_vendor: &str) -> Self {
        self.for_preset_on(preset, &HostCpu::vendor_only(cpu_vendor))
    }

    /// [`for_preset`](Self::for_preset) with the host's CPU generation known.
    pub fn for_preset_on(&self, preset: StealthPreset, host: &HostCpu) -> Self {
        match preset {
            StealthPreset::Transparent => Self::transparent(),
            StealthPreset::Custom => Self {
                preset,
                ..self.clone()
            },
            StealthPreset::CloudVps => Self::cloud_vps(&CLOUDS[0]),
            kind => Self::realistic_on(kind, host),
        }
    }

    /// Switch to `machine`'s firmware strings with new serials.
    pub fn use_machine(&mut self, machine: &MachineProfile) {
        self.identity = MachineIdentity::from_machine(machine);
        self.cloud.clear();
        self.machine = MachineType::Q35;
        self.identity_enabled = true;
        self.disk_media = DiskMedia::of_rotation(self.identity.disk_rotation);
    }

    /// Where a base that names its NIC by slot gets the network card: the
    /// integrated LAN's place on the chipset of the machine the identity
    /// copies; 00:19.0 without one (Transparent, an edited identity).
    pub fn nic_slot(&self) -> NicSlot {
        if self.machine == MachineType::Pc {
            return NicSlot::Pc;
        }
        if !self.identity_enabled {
            return NicSlot::Ich;
        }
        MACHINES
            .iter()
            .find(|machine| machine.id == self.identity.profile)
            .map_or(NicSlot::Ich, |machine| machine.nic_slot)
    }

    /// The machine this profile looks like, as a person would say it.
    pub fn machine_name(&self) -> String {
        if !self.identity_enabled {
            return "Transparent (QEMU's own identity)".into();
        }
        if let Some(machine) = MACHINES
            .iter()
            .find(|machine| machine.id == self.identity.profile)
        {
            return machine.label.into();
        }
        let name = format!(
            "{} {}",
            self.identity.system_manufacturer, self.identity.system_product
        );
        match name.trim() {
            "" => "a custom profile".into(),
            name => format!("{name} (edited)"),
        }
    }

    /// A warning when the host's CPU, which passthrough shows to the guest, did
    /// not ship in the machine this profile looks like.
    pub fn cpu_note(&self, host: &HostCpu) -> Option<String> {
        if !self.identity_enabled || !self.cpu_passthrough {
            return None;
        }
        let machine = MACHINES
            .iter()
            .find(|machine| machine.id == self.identity.profile)?;
        if machine.fits(host)? {
            return None;
        }
        Some(format!(
            "This host's CPU ({}) is shown to the guest, but no {} shipped with one; \
             pick another machine or name a CPU model.",
            host.generation?.label(),
            machine.label
        ))
    }

    /// Whether `machine` comes with an optical drive (QEMU's names QEMU).
    pub fn machine_has_cdrom(machine: &MachineProfile) -> bool {
        machine.cdrom
    }

    /// A new random MAC address with the network card's vendor prefix.
    pub fn new_mac(&mut self) {
        match self.cloud_provider() {
            Some(provider) if provider.mac_prefix.is_none() => self.new_local_mac(),
            Some(provider) => self.mac = random_mac(provider.mac_prefix.unwrap_or([0x52, 0x54, 0])),
            None => self.mac = random_mac(self.nic.mac_prefix()),
        }
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
                &identity.board_version,
                &identity.board_location,
                &identity.chassis_serial,
                &identity.chassis_manufacturer,
                &identity.cpu_manufacturer,
                &identity.cpu_version,
                &identity.chassis_version,
                &identity.chassis_sku,
                &identity.cpu_socket,
                &identity.cpu_part,
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
            if identity.oem_strings.len() > 16
                || identity.oem_strings.iter().any(|text| {
                    text.is_empty() || text.len() > 128 || text.chars().any(char::is_control)
                })
            {
                return Err("OEM strings: at most 16, each 1 to 128 characters".into());
            }
            if identity.memory_slots.len() > 8
                || identity.memory_slots.iter().any(|slot| {
                    [&slot.locator, &slot.bank]
                        .iter()
                        .any(|text| text.len() > 64 || text.chars().any(char::is_control))
                })
            {
                return Err("Memory slots: at most 8, names up to 64 characters".into());
            }
            if !identity.disk_wwn.is_empty()
                && (identity.disk_wwn.len() != 16
                    || !identity.disk_wwn.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err("The disk WWN is 16 hex digits".into());
            }
            if !identity.nic_subsystem.is_empty()
                && launch::pci_ids(&identity.nic_subsystem).is_none()
            {
                return Err(
                    "The network card's subsystem is vendor:device in hex (17aa:3179)".into(),
                );
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
        if [&self.cpu_model, &self.cpu_brand]
            .iter()
            .any(|text| text.len() > 64 || text.chars().any(|c| c.is_control() || c == '='))
        {
            return Err("CPU model and brand: at most 64 characters, no '='".into());
        }
        if !self
            .cpu_model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
        {
            return Err(format!("{:?} is not a QEMU CPU model name", self.cpu_model));
        }
        if !self.cloud.is_empty() && self.cloud_provider().is_none() {
            return Err(format!("{:?} is not a known cloud provider", self.cloud));
        }
        self.nat.validate()?;
        Ok(())
    }

    /// What still tells a VM apart, most telling first.
    pub fn giveaways(&self) -> Vec<&'static str> {
        if self.cloud_provider().is_some() {
            return self.cloud_giveaways();
        }
        let mut found = Vec::new();
        if !self.hide_hypervisor {
            found.push("CPUID hypervisor flag");
        }
        if !self.hide_kvm {
            found.push(if self.kvm_clock {
                "KVM CPUID signature and kvm-clock"
            } else {
                "KVM CPUID signature"
            });
        }
        if !self.identity_enabled {
            found.push("QEMU in the SMBIOS and ACPI tables, chassis type Other");
        }
        if !self.cpu_passthrough {
            found.push(if self.cpu_brand.is_empty() {
                "QEMU CPU model name"
            } else {
                "the QEMU CPU model's family and model numbers behind its brand"
            });
        }
        if self.mac.is_empty() {
            found.push("QEMU's MAC address 52:54:00:12:34:56");
        }
        if self.nic == NicModel::VirtioNet {
            found.push("virtio network card (Red Hat vendor ID)");
        } else if self.identity_enabled
            && let Some(machine) = MACHINES
                .iter()
                .find(|machine| machine.id == self.identity.profile)
        {
            found.extend(machine.nic_fit().giveaway());
        }
        match self.disk_bus {
            DiskBus::Virtio => found.push("virtio disk vda (Red Hat vendor ID)"),
            DiskBus::Sata if !self.identity_enabled || self.identity.disk_model.is_empty() => {
                found.push("SATA disk model QEMU HARDDISK")
            }
            DiskBus::Sata => {}
            DiskBus::Nvme => {
                found.push("NVMe controller model QEMU NVMe Ctrl, QEMU's version as firmware, an org.qemu subsystem name")
            }
        }
        if self.cdrom {
            found.push("the CD-ROM's SCSI inquiry: QEMU DVD-ROM");
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
        match self.firmware {
            Firmware::Bios => found.push("BIOS firmware (SeaBIOS): no /sys/firmware/efi"),
            _ => found.push("OVMF's vendor (EDK II) in the EFI tables, to root"),
        }
        if self.nat.network.is_empty() {
            found.push("QEMU user-network addresses (10.0.2.x) on NAT");
        }
        if self.pointer != Pointer::Ps2 {
            found.push("the pointer's input name (QEMU) in the VM window");
        }
        // Not covered by any entry: needed by Antinomie, outside QEMU options
        // or beyond what the guest kernel can hide (docs/implementation.md,
        // "Guest stealth").
        found.extend([
            "timing of VM exits (CPUID, I/O) and of traced calls",
            "the emulated display (Bochs or virtio-gpu)",
            "q35 chipset layout, Red Hat PCI subsystem IDs on the chipset's devices",
            "QEMU's ACPI tables to root (BXPC creator ID, fw_cfg in the DSDT)",
            "a fresh boot: minutes of uptime",
        ]);
        found
    }

    /// What still tells a cloud profile from an instance of the provider.
    fn cloud_giveaways(&self) -> Vec<&'static str> {
        let mut found =
            vec!["the QEMU/KVM hypervisor, visible by design as on the provider's machines"];
        if self.nat.network.is_empty() {
            found.push("QEMU user-network addresses (10.0.2.x) on NAT");
        }
        found.extend([
            "the metadata service answers only on a Routed network",
            "the emulated display (Bochs or virtio-gpu), not the provider's Cirrus, QXL or Bochs",
            "PCI subsystem IDs and the provider's own PCI bridges and balloon device",
            "DNS servers inside the DHCP network, not the provider's",
            "no provider agent process runs (files and stubs only)",
            "a fresh boot: minutes of uptime",
        ]);
        found
    }

    /// This profile as the base and the host can boot it, and what changed:
    /// an entry they lack falls back to the choice every base and host has.
    pub fn fitted(&self, base: &BaseSupport, host: &HostSupport) -> (Self, Vec<String>) {
        let (fitted, fallbacks) = self.fitted_with(base, host);
        (fitted, fallbacks.iter().map(Fallback::note).collect())
    }

    /// [`fitted`](Self::fitted) with each difference as a [`Fallback`], so a
    /// window can put it beside its setting and a log can list it.
    pub fn fitted_with(&self, base: &BaseSupport, host: &HostSupport) -> (Self, Vec<Fallback>) {
        let mut fitted = self.clone();
        let fallbacks = self.fallbacks(base, host);
        for fallback in &fallbacks {
            match fallback.setting {
                FallbackSetting::Firmware => fitted.firmware = Firmware::Bios,
                FallbackSetting::DiskBus => fitted.disk_bus = DiskBus::Virtio,
                FallbackSetting::Nat => fitted.nat = NatNetwork::default(),
                FallbackSetting::Smt => fitted.smt = false,
                FallbackSetting::Pointer => fitted.pointer = Pointer::VirtioTablet,
            }
        }
        if fitted.firmware == Firmware::UefiSecureBoot {
            fitted.smm = true;
        }
        (fitted, fallbacks)
    }

    /// What this profile asks for that the base or the host cannot give, in
    /// the order the settings are fitted. Empty when everything is supported.
    pub fn fallbacks(&self, base: &BaseSupport, host: &HostSupport) -> Vec<Fallback> {
        let mut found = Vec::new();
        if let Some(reason) = firmware_unavailable(self.firmware, base, host) {
            let cause = if self.firmware.is_uefi() && !base.uefi {
                "this base"
            } else {
                "this host"
            };
            found.push(Fallback {
                setting: FallbackSetting::Firmware,
                summary: format!(
                    "{} not supported by {cause}: BIOS will be used",
                    self.firmware.label()
                ),
                note: format!("{}: {reason}; BIOS used", self.firmware.label()),
                reason,
            });
        }
        if let Some(reason) = disk_bus_unavailable(self.disk_bus, base) {
            found.push(Fallback {
                setting: FallbackSetting::DiskBus,
                summary: format!(
                    "{} not supported by this base: virtio will be used",
                    self.disk_bus.label()
                ),
                note: format!("{} disk: {reason}; virtio used", self.disk_bus.label()),
                reason: reason.into(),
            });
        }
        if !self.nat.network.is_empty() && !base.dhcp {
            found.push(Fallback {
                setting: FallbackSetting::Nat,
                summary: format!(
                    "Guest network {} needs a base with DHCP (built by 0.7.0 or later); \
                     10.0.2.0/24 is used instead.",
                    self.nat.network
                ),
                note: format!(
                    "Guest network {}: {NAT_STATIC}; 10.0.2.0/24 used instead",
                    self.nat.network
                ),
                reason: NAT_STATIC.into(),
            });
        }
        if self.smt
            && self.realistic_topology
            && let Err(reason) = &host.smt
        {
            found.push(Fallback {
                setting: FallbackSetting::Smt,
                summary: "Two threads per core not supported by this host: one will be used".into(),
                note: format!("Two threads per core: {reason}; one used"),
                reason: reason.clone(),
            });
        }
        if self.pointer == Pointer::UsbTablet && !self.usb {
            found.push(Fallback {
                setting: FallbackSetting::Pointer,
                summary: "USB tablet needs a USB controller: virtio tablet will be used".into(),
                note: "USB tablet: no USB controllers; virtio tablet used".into(),
                reason: "no USB controllers".into(),
            });
        }
        found
    }

    /// How common checks (systemd-detect-virt, DMI strings, the CPUID
    /// hypervisor bit, MAC prefixes) would rate this VM.
    pub fn rating(&self) -> &'static str {
        if self.cloud_provider().is_some() {
            // A cloud instance is a KVM guest by design: the checks that
            // call this a VM call every machine of the provider one.
            return "unlikely";
        }
        if !self.hide_hypervisor || !self.hide_kvm || !self.identity_enabled {
            "certain"
        } else if self.mac.is_empty() || !self.cpu_passthrough || self.nic == NicModel::VirtioNet {
            "possible"
        } else {
            "unlikely"
        }
    }
}

/// A setting `fitted` changes: the profile asks for something the base, the
/// host or the profile itself cannot give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackSetting {
    Firmware,
    DiskBus,
    Nat,
    Smt,
    Pointer,
}

/// One difference between what a profile asks for and what a VM starts with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fallback {
    pub setting: FallbackSetting,
    /// One line for the setting itself: `SATA not supported by this base:
    /// virtio will be used`.
    pub summary: String,
    /// Why, and what to do about it.
    pub reason: String,
    /// The long form, as the Still visible list and logs read it.
    note: String,
}

impl Fallback {
    pub fn note(&self) -> String {
        self.note.clone()
    }

    /// The line a start log and a run's notes carry.
    pub fn log_line(&self) -> String {
        format!(
            "Device profile setting not applied: {}; {}",
            self.summary.trim_end_matches('.'),
            self.reason
        )
    }
}

/// The base a VM starts from: the one it names, else the first installed
/// base that is not a graphical guest base, else the first.
pub fn vm_base<'a>(
    identity: Option<&str>,
    bases: &'a [crate::api::BaseSummary],
) -> Option<&'a crate::api::BaseSummary> {
    if let Some(identity) = identity {
        return bases.iter().find(|base| base.id == identity);
    }
    bases
        .iter()
        .find(|base| base.guest.is_none())
        .or_else(|| bases.first())
}

/// What a VM's profile asks for that its base or this host cannot give. A VM
/// whose base is not installed has nothing to compare with: empty.
pub fn vm_fallbacks(
    vm: &crate::api::VmConfig,
    bases: &[crate::api::BaseSummary],
    host: &HostSupport,
) -> Vec<Fallback> {
    vm_base(vm.base_identity.as_deref(), bases).map_or_else(Vec::new, |base| {
        vm.stealth
            .fallbacks(&BaseSupport::from_list(&base.stealth_support), host)
    })
}

/// An installed base, other than `current`, that supports every setting this
/// profile has fallen back on for `setting`: where the user can switch to get
/// what the profile asks for.
pub fn base_supporting<'a>(
    profile: &StealthProfile,
    setting: FallbackSetting,
    current: Option<&str>,
    bases: &'a [crate::api::BaseSummary],
    host: &HostSupport,
) -> Option<&'a crate::api::BaseSummary> {
    bases
        .iter()
        .filter(|base| Some(base.id.as_str()) != current)
        .find(|base| {
            let support = BaseSupport::from_list(&base.stealth_support);
            !profile
                .fallbacks(&support, host)
                .iter()
                .any(|fallback| fallback.setting == setting)
        })
}

/// Why an older base keeps QEMU's 10.0.2.0/24 network.
const NAT_STATIC: &str = "this base sets 10.0.2.15 itself";

/// What a base boots with besides virtio, SeaBIOS and 10.0.2.0/24, from its
/// `bundle.json` (`stealth_support`, written by the image builders).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BaseSupport {
    /// The kernel keeps the bootstrap page out of its EFI stub's placement.
    pub uefi: bool,
    pub sata: bool,
    pub nvme: bool,
    /// The guest takes its address from DHCP, so any NAT network works.
    pub dhcp: bool,
    /// The guest's network configuration names its NIC by its PCI slot
    /// (`onboardnic`): the NIC goes to the profile's [`NicSlot`], whatever
    /// its model, and provisioning writes the stanza for that interface.
    pub onboard_nic: bool,
}

impl BaseSupport {
    pub fn from_list(list: &[String]) -> Self {
        let has = |name: &str| list.iter().any(|item| item == name);
        Self {
            uefi: has("uefi"),
            sata: has("sata"),
            nvme: has("nvme"),
            dhcp: has("dhcp"),
            onboard_nic: has("onboardnic"),
        }
    }

    /// Everything, for a profile not yet tied to a base.
    pub fn all() -> Self {
        Self {
            uefi: true,
            sata: true,
            nvme: true,
            dhcp: true,
            onboard_nic: true,
        }
    }
}

/// What the host offers: OVMF and clean SMT topology.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSupport {
    pub ovmf: Result<(), String>,
    pub ovmf_secure_boot: Result<(), String>,
    pub smt: Result<(), String>,
}

impl HostSupport {
    /// The host as `qemu` sees it.
    pub fn detect(qemu: &std::path::Path) -> Self {
        Self {
            ovmf: find_ovmf(qemu, false).map(|_| ()),
            ovmf_secure_boot: find_ovmf(qemu, true).map(|_| ()),
            smt: smt_clean(
                &host_cpu_vendor(),
                &host_cpuinfo("flags").unwrap_or_default(),
            ),
        }
    }

    /// The host as `qemu-system-x86_64` on the path sees it, read once.
    pub fn cached() -> &'static Self {
        static HOST: std::sync::OnceLock<HostSupport> = std::sync::OnceLock::new();
        HOST.get_or_init(|| Self::detect(std::path::Path::new("qemu-system-x86_64")))
    }

    pub fn all() -> Self {
        Self {
            ovmf: Ok(()),
            ovmf_secure_boot: Ok(()),
            smt: Ok(()),
        }
    }
}

/// Two threads per core without QEMU's warning: Intel CPUs report them in
/// their leaf 4 and 0xb topology; AMD CPUs need the TOPOEXT leaves, which
/// the launch adds when the host CPU has them.
fn smt_clean(cpu_vendor: &str, flags: &str) -> Result<(), String> {
    match cpu_vendor {
        "GenuineIntel" => Ok(()),
        "AuthenticAMD" | "HygonGenuine"
            if flags.split_whitespace().any(|flag| flag == "topoext") =>
        {
            Ok(())
        }
        "AuthenticAMD" | "HygonGenuine" => Err(
            "the host CPU lacks TOPOEXT, without which QEMU warns that this AMD CPU has no SMT"
                .into(),
        ),
        _ => Err("unknown host CPU vendor".into()),
    }
}

/// Why `firmware` cannot be used with this base and host.
pub fn firmware_unavailable(
    firmware: Firmware,
    base: &BaseSupport,
    host: &HostSupport,
) -> Option<String> {
    if !firmware.is_uefi() {
        return None;
    }
    if !base.uefi {
        return Some(
            "the base's kernel can land on the transport page under UEFI (rebuild it)".into(),
        );
    }
    let found = if firmware == Firmware::UefiSecureBoot {
        &host.ovmf_secure_boot
    } else {
        &host.ovmf
    };
    found.as_ref().err().cloned()
}

/// Why the base cannot boot from a disk on `bus`.
pub fn disk_bus_unavailable(bus: DiskBus, base: &BaseSupport) -> Option<&'static str> {
    match bus {
        DiskBus::Virtio => None,
        DiskBus::Sata if base.sata => None,
        DiskBus::Nvme if base.nvme => None,
        _ => Some("the base boots from virtio only (rebuild a BusyBox base; Debian keeps virtio)"),
    }
}

/// Why the base cannot use a guest network of its own.
pub fn nat_unavailable(base: &BaseSupport) -> Option<&'static str> {
    (!base.dhcp).then_some(NAT_STATIC)
}

/// What pafish-style checks flag in the VM's size, with a real machine's.
pub fn resource_hints(cpus: u16, ram_mib: u32, disk_gib: u32) -> Vec<&'static str> {
    let mut hints = Vec::new();
    if cpus < 2 {
        hints.push("1 CPU: checks flag fewer than 2; PCs have 4 to 16 threads");
    }
    if ram_mib < 4096 {
        hints.push("under 4 GiB RAM: checks flag it; PCs have 8 to 32 GiB");
    }
    if disk_gib < 64 {
        hints.push("a disk under 60 GiB: checks flag it; PCs have 256 GiB or more (a BusyBox base grows its filesystem on the first boot: for 256 GiB about 400 MiB of image and two minutes)");
    }
    hints
}
