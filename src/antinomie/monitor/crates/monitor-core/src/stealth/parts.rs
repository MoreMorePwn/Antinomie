// SPDX-License-Identifier: GPL-3.0-only
//! Real storage and memory parts a machine's identity picks from. Only
//! factual identifiers: the model, firmware and part strings such parts report.

/// A SATA SSD as its IDENTIFY data names it.
pub(super) struct DiskModel {
    pub model: &'static str,
    pub firmware: &'static str,
    /// The maker's IEEE OUI (six hex digits), the middle of the WWN.
    pub oui: &'static str,
    /// The start of its serial numbers, and the characters and count of the
    /// rest.
    pub serial_prefix: &'static str,
    pub serial_alphabet: &'static [u8],
    pub serial_tail: usize,
}

const UPPER: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const HEX: &[u8] = b"0123456789ABCDEF";

/// What business desktops and laptops ship with or get upgraded to.
pub(super) const CLIENT_DISKS: &[DiskModel] = &[
    DiskModel {
        model: "Samsung SSD 870 EVO 500GB",
        firmware: "SVT02B6Q",
        oui: "002538",
        serial_prefix: "S6PXNF0T",
        serial_alphabet: UPPER,
        serial_tail: 7,
    },
    DiskModel {
        model: "Samsung SSD 870 EVO 1TB",
        firmware: "SVT02B6Q",
        oui: "002538",
        serial_prefix: "S626NF0R",
        serial_alphabet: UPPER,
        serial_tail: 7,
    },
    DiskModel {
        model: "Samsung SSD 860 EVO 500GB",
        firmware: "RVT04B6Q",
        oui: "002538",
        serial_prefix: "S3Z2NB0K",
        serial_alphabet: UPPER,
        serial_tail: 7,
    },
    DiskModel {
        model: "CT500MX500SSD1",
        firmware: "M3CR033",
        oui: "00a075",
        serial_prefix: "21",
        serial_alphabet: HEX,
        serial_tail: 10,
    },
    DiskModel {
        model: "WDC WDS500G2B0A-00SM50",
        firmware: "415020WD",
        oui: "001b44",
        serial_prefix: "21",
        serial_alphabet: DIGITS,
        serial_tail: 10,
    },
    DiskModel {
        model: "KINGSTON SA400S37480G",
        firmware: "SBFK71E0",
        oui: "0026b7",
        serial_prefix: "50026B7685",
        serial_alphabet: HEX,
        serial_tail: 6,
    },
];

/// What entry servers ship with.
pub(super) const SERVER_DISKS: &[DiskModel] = &[
    DiskModel {
        model: "INTEL SSDSC2KB480G8",
        firmware: "XCV10132",
        oui: "5cd2e4",
        serial_prefix: "BTYF",
        serial_alphabet: UPPER,
        serial_tail: 12,
    },
    DiskModel {
        model: "SAMSUNG MZ7LH480HAHQ-00005",
        firmware: "HXT7404Q",
        oui: "002538",
        serial_prefix: "S45PNE0M",
        serial_alphabet: UPPER,
        serial_tail: 6,
    },
    DiskModel {
        model: "Micron_5300_MTFDDAK480TDS",
        firmware: "D3MU001",
        oui: "00a075",
        serial_prefix: "20",
        serial_alphabet: HEX,
        serial_tail: 10,
    },
];

/// A memory module as its SPD names it.
pub(super) struct RamPart {
    pub manufacturer: &'static str,
    pub part: &'static str,
}

/// SO-DIMMs, for laptops.
pub(super) const LAPTOP_RAM: &[RamPart] = &[
    RamPart {
        manufacturer: "Samsung",
        part: "M471A1K43DB1-CWE",
    },
    RamPart {
        manufacturer: "Samsung",
        part: "M471A2K43DB1-CWE",
    },
    RamPart {
        manufacturer: "Micron Technology",
        part: "8ATF1G64HZ-3G2E1",
    },
    RamPart {
        manufacturer: "SK Hynix",
        part: "HMA81GS6DJR8N-XN",
    },
    RamPart {
        manufacturer: "Crucial Technology",
        part: "CT8G4SFRA32A.M8FR",
    },
];

/// Unbuffered DIMMs, for desktops.
pub(super) const DESKTOP_RAM: &[RamPart] = &[
    RamPart {
        manufacturer: "Samsung",
        part: "M378A1K43DB2-CTD",
    },
    RamPart {
        manufacturer: "Samsung",
        part: "M378A2K43EB1-CWE",
    },
    RamPart {
        manufacturer: "Micron Technology",
        part: "8ATF1G64AZ-3G2E1",
    },
    RamPart {
        manufacturer: "SK Hynix",
        part: "HMA81GU6DJR8N-XN",
    },
    RamPart {
        manufacturer: "Crucial Technology",
        part: "CT8G4DFRA32A.M8FR",
    },
];

/// ECC unbuffered DIMMs, for servers.
pub(super) const SERVER_RAM: &[RamPart] = &[
    RamPart {
        manufacturer: "Samsung",
        part: "M391A2K43BB1-CTD",
    },
    RamPart {
        manufacturer: "Micron Technology",
        part: "18ASF2G72AZ-3G2B1",
    },
    RamPart {
        manufacturer: "SK Hynix",
        part: "HMA82GU7CJR8N-VK",
    },
];
