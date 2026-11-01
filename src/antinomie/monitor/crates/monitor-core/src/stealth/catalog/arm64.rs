// SPDX-License-Identifier: GPL-3.0-only
//! arm64 machines an arm64 VM booting through UEFI presents (MA-17): Ampere
//! Altra servers and workstation and an AWS Graviton2 instance. Every value
//! is cited in `SOURCES-arm64.md` with its class (A seen in a public report of
//! this machine, B of another model of the maker, C recollection or derived).

/// What kind of machine, matched to the device profile's preset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmKind {
    Server,
    Workstation,
    Cloud,
    /// A single-board computer booted on its device tree (no UEFI, no
    /// SMBIOS), as a Raspberry Pi.
    Board,
}

/// What a board's device tree names: the root's model, compatible list and
/// the firmware's serial number prefix (the rest from the VM's UUID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardTree {
    pub model: &'static str,
    pub compatible: &'static [&'static str],
    pub serial_prefix: &'static str,
    /// The cores' caches as the board's tree describes them (bytes, ways):
    /// L1 instruction and data per core, L2 per core or per cluster, L3
    /// (0: none).
    pub l1i: (u32, u32),
    pub l1d: (u32, u32),
    pub l2: (u32, u32, bool),
    pub l3: (u32, u32),
}

/// A cloud instance type by its vCPUs and memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmPlan {
    pub name: &'static str,
    pub cpus: u16,
    pub ram_mib: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmMachine {
    pub id: &'static str,
    pub label: &'static str,
    pub kind: ArmKind,
    /// QEMU's CPU model, its MIDR_EL1 and the generic timer's frequency.
    pub cpu: &'static str,
    pub midr: u32,
    pub cntfrq_hz: u64,
    /// SMBIOS type 4: maker, version, socket and speed in MHz.
    pub cpu_manufacturer: &'static str,
    pub cpu_version: &'static str,
    pub cpu_socket: &'static str,
    pub cpu_mhz: u16,
    /// Vendor, version and release date of the firmware (type 0), and its
    /// "system is a virtual machine" bit.
    pub bios: (&'static str, &'static str, &'static str),
    pub virtual_machine: bool,
    /// Manufacturer, product, version, family and SKU (type 1); a cloud's
    /// product is its instance type, from `plans`.
    pub system: (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    ),
    /// Manufacturer, product and version of the board (type 2).
    pub board: (&'static str, &'static str, &'static str),
    /// Manufacturer, SMBIOS type (23 rack mount, 17 main server chassis,
    /// 1 other) and version of the chassis (type 3).
    pub chassis: (&'static str, u8, &'static str),
    /// The system serial: `#` is a digit, `@` a capital letter; empty: the
    /// UUID (a cloud's).
    pub serial: &'static str,
    /// Memory maker and part, speed in MT/s, first slot's locator, and
    /// whether the modules are registered ECC DIMMs.
    pub memory: (&'static str, &'static str, u16, &'static str, bool),
    /// ACPI table header OEM ID and OEM table ID.
    pub acpi: (&'static str, &'static str),
    /// The network card's vendor part of the MAC address; None: a random
    /// locally administered address, as a cloud numbers its interfaces.
    pub mac_prefix: Option<[u8; 3]>,
    /// The SATA disk's model and firmware revision.
    pub disk: (&'static str, &'static str),
    pub plans: &'static [ArmPlan],
    /// A board's device tree; None for the UEFI machines.
    pub tree: Option<BoardTree>,
}

const fn plan(name: &'static str, cpus: u16, ram_mib: u32) -> ArmPlan {
    ArmPlan {
        name,
        cpus,
        ram_mib,
    }
}

/// Neoverse N1 r3p1, as Ampere Altra and AWS Graviton2 have it.
const NEOVERSE_N1_R3P1: u32 = 0x413f_d0c1;

pub const ARM_MACHINES: &[ArmMachine] = &[
    ArmMachine {
        id: "arm-gigabyte-r272-p33",
        label: "Giga Computing R272-P33 (Ampere Altra)",
        kind: ArmKind::Server,
        cpu: "neoverse-n1",
        midr: NEOVERSE_N1_R3P1,
        cntfrq_hz: 25_000_000,
        cpu_manufacturer: "Ampere(TM)",
        cpu_version: "Ampere(R) Altra(R) Processor",
        cpu_socket: "CPU 0",
        cpu_mhz: 3000,
        bios: ("GIGABYTE", "F33j (SCP: 2.10.20220531)", "06/16/2022"),
        virtual_machine: false,
        system: ("GIGABYTE", "R272-P33-00", "0100", "Server", ""),
        board: ("GIGABYTE", "MP32-AR1-00", "01000100"),
        chassis: ("GIGABYTE", 23, "01234567"),
        serial: "GJ@#N#######",
        memory: ("Samsung", "M393A2K43DB3-CWE", 3200, "DIMM_P0_A0", true),
        acpi: ("Ampere", "Altra"),
        mac_prefix: Some([0xe0, 0xd5, 0x5e]),
        disk: ("SAMSUNG MZ7LH480HAHQ-00005", "HXT7404Q"),
        plans: &[],
        tree: None,
    },
    ArmMachine {
        id: "arm-hpe-rl300-gen11",
        label: "HPE ProLiant RL300 Gen11 (Ampere Altra)",
        kind: ArmKind::Server,
        cpu: "neoverse-n1",
        midr: NEOVERSE_N1_R3P1,
        cntfrq_hz: 25_000_000,
        cpu_manufacturer: "Ampere(TM)",
        cpu_version: "Ampere(R) Altra(R) Processor",
        cpu_socket: "Proc 1",
        cpu_mhz: 3000,
        bios: ("HPE", "1.10", "08/04/2022"),
        virtual_machine: false,
        system: ("HPE", "ProLiant RL300 Gen11", "", "ProLiant", ""),
        board: ("HPE", "ProLiant RL300 Gen11", ""),
        chassis: ("HPE", 23, ""),
        serial: "CZ##@#####",
        memory: ("Samsung", "M393A4K40DB3-CWE", 3200, "PROC 1 DIMM 1", true),
        acpi: ("HPE", "Server"),
        mac_prefix: Some([0xa0, 0x36, 0x9f]),
        disk: ("MICRON_5300_MTFDDAK480TDS", "D3MU001"),
        plans: &[],
        tree: None,
    },
    ArmMachine {
        id: "arm-adlink-altra-dev",
        label: "ADLINK Ampere Altra Developer Platform",
        kind: ArmKind::Workstation,
        cpu: "neoverse-n1",
        midr: NEOVERSE_N1_R3P1,
        cntfrq_hz: 25_000_000,
        cpu_manufacturer: "Ampere(TM)",
        cpu_version: "Ampere(R) Altra(R) Processor",
        cpu_socket: "CPU 0",
        cpu_mhz: 2200,
        bios: (
            "ADLINK",
            "TianoCore 2.04.100.04 (SYS: 2..6.20220308)",
            "03/08/2022",
        ),
        virtual_machine: false,
        system: (
            "ADLINK Technology Inc.",
            "Ampere Altra Developer Platform",
            "Rev.A1",
            "AVA",
            "",
        ),
        board: ("ADLINK Technology Inc.", "COM-HPC-ALT", "A1"),
        chassis: ("ADLINK Technology Inc.", 17, ""),
        serial: "@##########",
        memory: ("Samsung", "M393A2K43DB3-CWE", 3200, "DIMM0", true),
        acpi: ("Ampere", "Altra"),
        mac_prefix: Some([0x00, 0x30, 0x64]),
        disk: ("SAMSUNG MZ7LH480HAHQ-00005", "HXT7404Q"),
        plans: &[],
        tree: None,
    },
    ArmMachine {
        id: "arm-aws-graviton2",
        label: "AWS EC2 Graviton2 instance",
        kind: ArmKind::Cloud,
        cpu: "neoverse-n1",
        midr: NEOVERSE_N1_R3P1,
        cntfrq_hz: 121_875_000,
        cpu_manufacturer: "AWS",
        cpu_version: "AWS Graviton2",
        cpu_socket: "CPU00",
        cpu_mhz: 2500,
        bios: ("Amazon EC2", "1.0", "11/1/2018"),
        virtual_machine: true,
        system: ("Amazon EC2", "t4g.micro", "", "", ""),
        board: ("Amazon EC2", "", ""),
        chassis: ("Amazon EC2", 1, ""),
        serial: "",
        memory: ("Not Specified", "Not Specified", 0, "Not Specified", false),
        acpi: ("AMAZON", "AMZNFACP"),
        mac_prefix: None,
        disk: ("Amazon Elastic Block Store", "2.0"),
        plans: &[
            plan("t4g.nano", 2, 512),
            plan("t4g.micro", 2, 1024),
            plan("t4g.small", 2, 2048),
            plan("t4g.medium", 2, 4096),
            plan("t4g.large", 2, 8192),
            plan("t4g.xlarge", 4, 16384),
            plan("t4g.2xlarge", 8, 32768),
        ],
        tree: None,
    },
    ArmMachine {
        id: "arm-rpi-4b",
        label: "Raspberry Pi 4 Model B",
        kind: ArmKind::Board,
        cpu: "cortex-a72",
        midr: 0x410f_d083,
        cntfrq_hz: 54_000_000,
        cpu_manufacturer: "",
        cpu_version: "",
        cpu_socket: "",
        cpu_mhz: 1800,
        bios: ("", "", ""),
        virtual_machine: false,
        system: ("", "", "", "", ""),
        board: ("", "", ""),
        tree: Some(BoardTree {
            model: "Raspberry Pi 4 Model B Rev 1.4",
            compatible: &["raspberrypi,4-model-b", "brcm,bcm2711"],
            serial_prefix: "10000000",
            l1i: (48 * 1024, 3),
            l1d: (32 * 1024, 2),
            l2: (1024 * 1024, 16, false),
            l3: (0, 0),
        }),
        chassis: ("", 0, ""),
        serial: "",
        memory: ("", "", 0, "", false),
        acpi: ("", ""),
        mac_prefix: Some([0xdc, 0xa6, 0x32]),
        disk: ("Samsung SSD 870 EVO 500GB", "SVT02B6Q"),
        plans: &[],
    },
    ArmMachine {
        id: "arm-rpi-5",
        label: "Raspberry Pi 5 Model B",
        kind: ArmKind::Board,
        cpu: "cortex-a76",
        midr: 0x414f_d0b1,
        cntfrq_hz: 54_000_000,
        cpu_manufacturer: "",
        cpu_version: "",
        cpu_socket: "",
        cpu_mhz: 2400,
        bios: ("", "", ""),
        virtual_machine: false,
        system: ("", "", "", "", ""),
        board: ("", "", ""),
        tree: Some(BoardTree {
            model: "Raspberry Pi 5 Model B Rev 1.0",
            compatible: &["raspberrypi,5-model-b", "brcm,bcm2712"],
            serial_prefix: "",
            l1i: (64 * 1024, 4),
            l1d: (64 * 1024, 4),
            l2: (512 * 1024, 8, true),
            l3: (2048 * 1024, 16),
        }),
        chassis: ("", 0, ""),
        serial: "",
        memory: ("", "", 0, "", false),
        acpi: ("", ""),
        mac_prefix: Some([0x2c, 0xcf, 0x67]),
        disk: ("Samsung SSD 870 EVO 500GB", "SVT02B6Q"),
        plans: &[],
    },
];

impl ArmMachine {
    pub fn find(id: &str) -> Option<&'static Self> {
        ARM_MACHINES.iter().find(|machine| machine.id == id)
    }

    /// The instance type of `cpus` vCPUs and `ram_mib`, else the closest
    /// in memory among those of `cpus` (None: no plan has that many).
    pub fn plan_for(&self, cpus: u16, ram_mib: u32) -> Option<&'static ArmPlan> {
        self.plans
            .iter()
            .filter(|plan| plan.cpus == cpus)
            .min_by_key(|plan| plan.ram_mib.abs_diff(ram_mib))
    }
}
