// SPDX-License-Identifier: GPL-3.0-only
//! SMBIOS structures QEMU's own options cannot fill as a PC's firmware does:
//! the BIOS information (type 0) and the chassis (type 3); the processor
//! (types 4 and 7) and memory (types 16 and 17) are in `processor` and
//! `memory`.
use super::MachineIdentity;

/// The BIOS release from its version string, as QEMU's `release=` takes it:
/// the first two numbers in it ("1.21.0" is 1.21).
pub(super) fn bios_release(version: &str) -> Option<(u8, u8)> {
    let mut numbers = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = numbers.next()?.parse::<u8>().unwrap_or(1);
    let minor = numbers.next()?.parse::<u8>().unwrap_or(0);
    Some((major, minor))
}

/// Strings of an SMBIOS structure: the formatted area's string numbers (0 for
/// an empty one) and the string set that follows it.
pub(super) fn string_set(strings: &[&str]) -> (Vec<u8>, Vec<u8>) {
    let mut numbers = Vec::new();
    let mut set = Vec::new();
    for text in strings {
        let bytes: Vec<u8> = text.bytes().filter(|byte| *byte != 0).collect();
        if bytes.is_empty() {
            numbers.push(0);
        } else {
            set.extend(bytes);
            set.push(0);
            numbers.push((set.iter().filter(|byte| **byte == 0).count()) as u8);
        }
    }
    if set.is_empty() {
        set.push(0);
    }
    set.push(0);
    (numbers, set)
}

/// An SMBIOS type 0 (BIOS information) structure, as a PC's firmware writes
/// it: what it supports, and not QEMU's "characteristics not supported" and
/// "system is a virtual machine" (extension byte 2, bit 4). UEFI firmware
/// also sets "UEFI is supported" (extension byte 2, bit 3).
pub(super) fn bios_table(id: &MachineIdentity, uefi: bool) -> Vec<u8> {
    let (numbers, strings) = string_set(&[&id.bios_vendor, &id.bios_version, &id.bios_date]);
    // PCI, PnP, flash upgradeable, shadowing, boot from CD, selectable boot,
    // EDD, the int 13h floppy services, int 5h, 9h, 14h, 17h and 10h.
    let characteristics: u64 = [7, 9, 11, 12, 15, 16, 19, 23, 24, 25, 26, 27, 28, 29, 30]
        .iter()
        .map(|bit| 1u64 << bit)
        .sum();
    let (major, minor) = bios_release(&id.bios_version).unwrap_or((0xff, 0xff));
    // Type 0, the formatted area's length (SMBIOS 3.1) and handle 0.
    let mut table = vec![0, 0x1a, 0, 0];
    // Vendor and version strings, starting address segment F000h.
    table.extend([numbers[0], numbers[1]]);
    table.extend(0xf000u16.to_le_bytes());
    // Release date string; the ROM size is in the extended field.
    table.extend([numbers[2], 0xff]);
    table.extend(characteristics.to_le_bytes());
    // Extension byte 1: ACPI, USB legacy. Byte 2: BIOS boot specification,
    // network boot, targeted content distribution (no VM bit), UEFI.
    table.extend([0x03, if uefi { 0x0f } else { 0x07 }]);
    // BIOS release; no embedded controller firmware.
    table.extend([major, minor, 0xff, 0xff]);
    table.extend(32u16.to_le_bytes()); // extended ROM size: 32 MiB
    table.extend(strings);
    table
}

/// An SMBIOS type 3 (chassis) structure with its strings. The asset tag is
/// string 0, as an untagged unit's.
pub(super) fn chassis_table(id: &MachineIdentity) -> Vec<u8> {
    let or_default = |text: &str| {
        if text.is_empty() {
            "Default string".to_owned()
        } else {
            text.to_owned()
        }
    };
    let (manufacturer, serial) = (
        or_default(&id.system_manufacturer),
        or_default(&id.chassis_serial),
    );
    let (numbers, strings) = string_set(&[
        &manufacturer,
        &id.chassis_version,
        &serial,
        "",
        &id.chassis_sku,
    ]);
    let mut table = vec![
        3,    // type: system enclosure or chassis
        0x16, // length of the formatted area
        0x00,
        0x03, // handle
        numbers[0],
        id.chassis_type.max(1),
        numbers[1], // version
        numbers[2], // serial number
        numbers[3], // asset tag
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
        0,          // no contained elements
        numbers[4], // SKU number
    ];
    table.extend(strings);
    table
}
