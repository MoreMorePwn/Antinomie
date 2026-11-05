// SPDX-License-Identifier: GPL-3.0-only
//! Real storage and memory parts a machine's identity picks from. Only
//! factual identifiers: the model, firmware and part strings such parts
//! report, each seen in a public report (`catalog/SOURCES.md`).

/// A SATA disk as its IDENTIFY data names it.
pub(super) struct DiskModel {
    pub model: &'static str,
    pub firmware: &'static str,
    /// The maker's IEEE OUI (six hex digits) in the disk's NAA 5 world wide
    /// name, as smartctl dumps of the model show it; empty for none.
    pub oui: &'static str,
    /// The start of its serial numbers, and the characters and count of the
    /// rest. Not from a source: public dumps hide serial numbers.
    pub serial_prefix: &'static str,
    pub serial_alphabet: &'static [u8],
    pub serial_tail: usize,
    /// 1 for an SSD, else the spindle speed in rpm.
    pub rotation: u16,
}

/// A memory module as the machine's firmware names it in SMBIOS type 17.
pub(super) struct RamPart {
    pub manufacturer: &'static str,
    pub part: &'static str,
    /// SMBIOS memory type: 0x1a DDR4, 0x22 DDR5, 0x23 LPDDR5.
    pub memory_type: u8,
    /// MT/s.
    pub speed: u16,
    pub rank: u8,
    /// SMBIOS form factor: 9 DIMM, 13 SO-DIMM, 1 other (soldered).
    pub form: u8,
    /// Total width in bits: 64, 72 with ECC, 32 for LPDDR5.
    pub width: u16,
    /// The module's size in MiB, as its part number names it.
    pub size_mib: u32,
}

const UPPER: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const HEX: &[u8] = b"0123456789ABCDEF";

/// HGST HTS541010A9E680.
pub(super) const HGST_HTS541010A9E680_JA0OA560: DiskModel = DiskModel {
    model: "HGST HTS541010A9E680",
    firmware: "JA0OA560",
    oui: "000cca",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 5400,
};

/// INTEL SSDSC2KB480G7.
pub(super) const INTEL_SSDSC2KB480G7: DiskModel = DiskModel {
    model: "INTEL SSDSC2KB480G7",
    firmware: "SCV10150",
    oui: "5cd2e4",
    serial_prefix: "BTYF",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 1,
};

/// KINGSTON SA400S37240G.
pub(super) const KINGSTON_SA400S37240G: DiskModel = DiskModel {
    model: "KINGSTON SA400S37240G",
    firmware: "SBFK71E0",
    oui: "0026b7",
    serial_prefix: "50026B7",
    serial_alphabet: HEX,
    serial_tail: 9,
    rotation: 1,
};

/// KINGSTON SUV400S37240G.
pub(super) const KINGSTON_SUV400S37240G: DiskModel = DiskModel {
    model: "KINGSTON SUV400S37240G",
    firmware: "0C3G37R5",
    oui: "",
    serial_prefix: "50026B7",
    serial_alphabet: HEX,
    serial_tail: 9,
    rotation: 1,
};

/// MTFDDAV256TBN-1AR15ABHA.
pub(super) const MTFDDAV256TBN_1AR15ABHA: DiskModel = DiskModel {
    model: "MTFDDAV256TBN-1AR15ABHA",
    firmware: "HPC0T12",
    oui: "00a075",
    serial_prefix: "",
    serial_alphabet: HEX,
    serial_tail: 12,
    rotation: 1,
};

/// MTFDDAV256TDL-1AW1ZABHA.
pub(super) const MTFDDAV256TDL_1AW1ZABHA: DiskModel = DiskModel {
    model: "MTFDDAV256TDL-1AW1ZABHA",
    firmware: "HPC0032",
    oui: "00a075",
    serial_prefix: "",
    serial_alphabet: HEX,
    serial_tail: 12,
    rotation: 1,
};

/// PNY CS900 240GB SSD.
pub(super) const PNY_CS900_240GB_SSD: DiskModel = DiskModel {
    model: "PNY CS900 240GB SSD",
    firmware: "CS900J13",
    oui: "f8db4c",
    serial_prefix: "PNY",
    serial_alphabet: DIGITS,
    serial_tail: 13,
    rotation: 1,
};

/// Samsung SSD 860 EVO 250GB.
pub(super) const SAMSUNG_SSD_860_EVO_250GB: DiskModel = DiskModel {
    model: "Samsung SSD 860 EVO 250GB",
    firmware: "RVT02B6Q",
    oui: "002538",
    serial_prefix: "S",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 1,
};

/// Samsung SSD 860 EVO M.2 500GB.
pub(super) const SAMSUNG_SSD_860_EVO_M_2_500GB: DiskModel = DiskModel {
    model: "Samsung SSD 860 EVO M.2 500GB",
    firmware: "RVT24B6Q",
    oui: "002538",
    serial_prefix: "S",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 1,
};

/// Samsung SSD 870 EVO 500GB.
pub(super) const SAMSUNG_SSD_870_EVO_500GB: DiskModel = DiskModel {
    model: "Samsung SSD 870 EVO 500GB",
    firmware: "SVT01B6Q",
    oui: "002538",
    serial_prefix: "S",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 1,
};

/// Samsung SSD 870 EVO 500GB.
pub(super) const SAMSUNG_SSD_870_EVO_500GB_SVT02B6Q: DiskModel = DiskModel {
    model: "Samsung SSD 870 EVO 500GB",
    firmware: "SVT02B6Q",
    oui: "002538",
    serial_prefix: "S",
    serial_alphabet: UPPER,
    serial_tail: 14,
    rotation: 1,
};

/// SanDisk SDSSDHII120G.
pub(super) const SANDISK_SDSSDHII120G: DiskModel = DiskModel {
    model: "SanDisk SDSSDHII120G",
    firmware: "X31200RL",
    oui: "001b44",
    serial_prefix: "",
    serial_alphabet: DIGITS,
    serial_tail: 12,
    rotation: 1,
};

/// ST1000DM010-2EP102.
pub(super) const ST1000DM010_2EP102_1001: DiskModel = DiskModel {
    model: "ST1000DM010-2EP102",
    firmware: "1001",
    oui: "000c50",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// ST1000LM049-2GH172.
pub(super) const ST1000LM049_2GH172: DiskModel = DiskModel {
    model: "ST1000LM049-2GH172",
    firmware: "SDM1",
    oui: "000c50",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// ST2000LM015-2E8174.
pub(super) const ST2000LM015_2E8174: DiskModel = DiskModel {
    model: "ST2000LM015-2E8174",
    firmware: "0001",
    oui: "000c50",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 5400,
};

/// TOSHIBA DT01ACA050.
pub(super) const TOSHIBA_DT01ACA050: DiskModel = DiskModel {
    model: "TOSHIBA DT01ACA050",
    firmware: "MS1OA8L0",
    oui: "000039",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// TOSHIBA MG03ACA300.
pub(super) const TOSHIBA_MG03ACA300: DiskModel = DiskModel {
    model: "TOSHIBA MG03ACA300",
    firmware: "FL1A",
    oui: "000039",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// TOSHIBA MQ04ABF100.
pub(super) const TOSHIBA_MQ04ABF100: DiskModel = DiskModel {
    model: "TOSHIBA MQ04ABF100",
    firmware: "100001",
    oui: "000039",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 5400,
};

/// TOSHIBA MQ04ABF100.
pub(super) const TOSHIBA_MQ04ABF100_100002: DiskModel = DiskModel {
    model: "TOSHIBA MQ04ABF100",
    firmware: "100002",
    oui: "000039",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 5400,
};

/// TOSHIBA-TR200.
pub(super) const TOSHIBA_TR200: DiskModel = DiskModel {
    model: "TOSHIBA-TR200",
    firmware: "SBFA15.2",
    oui: "00080d",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 1,
};

/// WDC WD10EZEX-08WN4A1.
pub(super) const WDC_WD10EZEX_08WN4A1: DiskModel = DiskModel {
    model: "WDC WD10EZEX-08WN4A1",
    firmware: "03.01A03",
    oui: "0014ee",
    serial_prefix: "WD-WCC",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// WDC WD10EZEX-75WN4A1.
pub(super) const WDC_WD10EZEX_75WN4A1: DiskModel = DiskModel {
    model: "WDC WD10EZEX-75WN4A1",
    firmware: "13057113",
    oui: "0014ee",
    serial_prefix: "WD-WCC",
    serial_alphabet: UPPER,
    serial_tail: 8,
    rotation: 7200,
};

/// X160EB.
pub(super) const X160EB: DiskModel = DiskModel {
    model: "X160EB",
    firmware: "SN07656",
    oui: "000000",
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 12,
    rotation: 1,
};

/// An NVMe drive as its Identify Controller data and PCI function name it
/// (shown by the guest facade for QEMU's controller).
pub(super) struct NvmeModel {
    pub model: &'static str,
    pub firmware: &'static str,
    /// The maker's IEEE OUI (six hex digits), as smartctl prints it.
    pub oui: &'static str,
    /// PCI vendor, device, subsystem vendor and subsystem device; the
    /// Identify data's VID and SSVID are the vendor and subsystem vendor.
    pub pci: (u16, u16, u16, u16),
    /// The start of its serial numbers, and the characters and count of the
    /// rest. Not from a source: public dumps hide serial numbers.
    pub serial_prefix: &'static str,
    pub serial_alphabet: &'static [u8],
    pub serial_tail: usize,
}

/// Samsung PM981a, Dell's part number suffix.
pub(super) const SAMSUNG_MZVLB256HBHQ_00000: NvmeModel = NvmeModel {
    model: "SAMSUNG MZVLB256HBHQ-00000",
    firmware: "EXH7201Q",
    oui: "002538",
    pci: (0x144d, 0xa808, 0x144d, 0xa801),
    serial_prefix: "S4GENX0",
    serial_alphabet: UPPER,
    serial_tail: 7,
};

/// Samsung PM981a, Lenovo's part number suffix.
pub(super) const SAMSUNG_MZVLB256HBHQ_000L7: NvmeModel = NvmeModel {
    model: "SAMSUNG MZVLB256HBHQ-000L7",
    firmware: "4M2QEXH7",
    oui: "002538",
    pci: (0x144d, 0xa808, 0x144d, 0xa801),
    serial_prefix: "S4ELNX0",
    serial_alphabet: UPPER,
    serial_tail: 7,
};

/// Samsung PM991a, HP's part number suffix.
pub(super) const SAMSUNG_MZVLQ256HAJD_000H1: NvmeModel = NvmeModel {
    model: "SAMSUNG MZVLQ256HAJD-000H1",
    firmware: "HPS4NFXV",
    oui: "002538",
    pci: (0x144d, 0xa809, 0x144d, 0xa801),
    serial_prefix: "S59ANA0",
    serial_alphabet: UPPER,
    serial_tail: 7,
};

/// Samsung PM9A1, Lenovo's part number suffix.
pub(super) const SAMSUNG_MZVL2512HCJQ_00BL7: NvmeModel = NvmeModel {
    model: "SAMSUNG MZVL2512HCJQ-00BL7",
    firmware: "CL2QGXA7",
    oui: "002538",
    pci: (0x144d, 0xa80a, 0x144d, 0xa801),
    serial_prefix: "S64KNX0",
    serial_alphabet: UPPER,
    serial_tail: 7,
};

/// Micron 2450.
pub(super) const MICRON_2450_MTFDKBA512TFK: NvmeModel = NvmeModel {
    model: "Micron_2450_MTFDKBA512TFK",
    firmware: "V5MA010",
    oui: "00a075",
    pci: (0x1344, 0x5411, 0x1344, 0x1100),
    serial_prefix: "2",
    serial_alphabet: DIGITS,
    serial_tail: 11,
};

/// Micron 2400 (MTFDKCD).
pub(super) const MICRON_MTFDKCD512TFK: NvmeModel = NvmeModel {
    model: "Micron MTFDKCD512TFK",
    firmware: "7003V5LN",
    oui: "00a075",
    pci: (0x1344, 0x5411, 0x1344, 0x1100),
    serial_prefix: "2",
    serial_alphabet: DIGITS,
    serial_tail: 11,
};

/// KIOXIA BG5.
pub(super) const KIOXIA_KBG50ZNS256G: NvmeModel = NvmeModel {
    model: "KBG50ZNS256G NVMe KIOXIA 256GB",
    firmware: "11200109",
    oui: "8ce38e",
    pci: (0x1e0f, 0x000c, 0x1e0f, 0x0001),
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 12,
};

/// KIOXIA BG4.
pub(super) const KIOXIA_KBG40ZNS256G: NvmeModel = NvmeModel {
    model: "KBG40ZNS256G BG4A KIOXIA",
    firmware: "AEMS0104",
    oui: "8ce38e",
    pci: (0x1e0f, 0x0001, 0x1e0f, 0x0001),
    serial_prefix: "",
    serial_alphabet: UPPER,
    serial_tail: 12,
};

/// SK hynix PC801, Dell's model string.
pub(super) const SK_HYNIX_PC801_1TB: NvmeModel = NvmeModel {
    model: "PC801 NVMe SK hynix 1TB",
    firmware: "51003141",
    oui: "ace42e",
    pci: (0x1c5c, 0x1959, 0x1c5c, 0x1959),
    serial_prefix: "SJ",
    serial_alphabet: UPPER,
    serial_tail: 14,
};

/// SK hynix BC711.
pub(super) const SK_HYNIX_BC711_256GB: NvmeModel = NvmeModel {
    model: "BC711 NVMe SK hynix 256GB",
    firmware: "41002131",
    oui: "ace42e",
    pci: (0x1c5c, 0x174a, 0x1c5c, 0x174a),
    serial_prefix: "CY",
    serial_alphabet: UPPER,
    serial_tail: 14,
};

/// Every NVMe model above, for finding an identity's drive by its model.
pub(super) const NVME_MODELS: &[&NvmeModel] = &[
    &SAMSUNG_MZVLB256HBHQ_00000,
    &SAMSUNG_MZVLB256HBHQ_000L7,
    &SAMSUNG_MZVLQ256HAJD_000H1,
    &SAMSUNG_MZVL2512HCJQ_00BL7,
    &MICRON_2450_MTFDKBA512TFK,
    &MICRON_MTFDKCD512TFK,
    &KIOXIA_KBG50ZNS256G,
    &KIOXIA_KBG40ZNS256G,
    &SK_HYNIX_PC801_1TB,
    &SK_HYNIX_BC711_256GB,
];
