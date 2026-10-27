// SPDX-License-Identifier: GPL-3.0-only
//! SMBIOS structures QEMU's own options cannot fill as a PC's firmware does:
//! the BIOS information (type 0), the chassis (type 3) and the memory
//! devices (type 17).
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

/// The handle of the first memory device: QEMU's, after its type 16 array.
const MEMORY_DEVICE_HANDLE: u16 = 0x1100;

/// SMBIOS type 17 (memory device) structures for `ram_mib` of memory, one
/// per module of at most 16 GiB as QEMU counts them in its type 16 array,
/// each in the next of the identity's slots: what a PC's firmware writes
/// for the identity's module (its type, speed, rank and width), in place of
/// QEMU's "RAM" of unknown width in "DIMM 0".
pub(super) fn memory_tables(id: &MachineIdentity, ram_mib: u64, ecc: bool) -> Vec<Vec<u8>> {
    const MODULE_MIB: u64 = 16 * 1024;
    let count = ram_mib.div_ceil(MODULE_MIB).max(1);
    (0..count)
        .map(|index| {
            let size = if index + 1 < count {
                MODULE_MIB
            } else {
                ram_mib - MODULE_MIB * (count - 1)
            };
            memory_table(id, index as usize, size, ecc)
        })
        .collect()
}

fn memory_table(id: &MachineIdentity, index: usize, size_mib: u64, ecc: bool) -> Vec<u8> {
    let slot = id.memory_slots.get(index);
    let (locator, bank) = slot.map_or((format!("DIMM{}", index + 1), String::new()), |slot| {
        (slot.locator.clone(), slot.bank.clone())
    });
    // A second module has a serial of its own.
    let serial: String = id
        .memory_serial
        .chars()
        .cycle()
        .skip(index)
        .take(id.memory_serial.len())
        .collect();
    let (numbers, strings) = string_set(&[
        &locator,
        &bank,
        &id.memory_manufacturer,
        &serial,
        "",
        &id.memory_part,
    ]);
    let handle = MEMORY_DEVICE_HANDLE + index as u16;
    let (size, extended) = match u16::try_from(size_mib) {
        Ok(size) if size < 0x7fff => (size, 0u32),
        _ => (0x7fff, u32::try_from(size_mib).unwrap_or(u32::MAX)),
    };
    // An identity saved before 0.8.0 recorded none of these: DDR4-3200,
    // rank 1, 64 bits (72 with ECC).
    let or = |value: u16, default: u16| if value == 0 { default } else { value };
    let speed = or(id.memory_speed, 3200);
    let total_width = or(id.memory_width, if ecc { 72 } else { 64 });
    let data_width = if total_width == 72 { 64 } else { total_width };
    // Millivolts: LPDDR5 runs at 0.5 V, DDR5 at 1.1 V, DDR4 at 1.2 V.
    let voltage: u16 = match id.memory_type {
        0x23 => 500,
        0x22 => 1100,
        _ => 1200,
    };
    let memory_type = if id.memory_type == 0 {
        0x1a
    } else {
        id.memory_type
    };
    let mut table = vec![17, 0x28];
    table.extend(handle.to_le_bytes());
    table.extend(0x1000u16.to_le_bytes()); // QEMU's type 16 array
    table.extend(0xfffeu16.to_le_bytes()); // no error information
    table.extend(total_width.to_le_bytes());
    table.extend(data_width.to_le_bytes());
    table.extend(size.to_le_bytes()); // MiB
    table.extend([
        id.memory_form.max(1),
        0,
        numbers[0],
        numbers[1],
        memory_type,
    ]);
    table.extend(id.memory_detail.to_le_bytes());
    table.extend(speed.to_le_bytes());
    table.extend([
        numbers[2],
        numbers[3],
        numbers[4],
        numbers[5],
        id.memory_rank.clamp(1, 15),
    ]);
    table.extend(extended.to_le_bytes());
    table.extend(speed.to_le_bytes()); // configured speed
    for _ in 0..3 {
        table.extend(voltage.to_le_bytes()); // minimum, maximum, configured
    }
    table.extend(strings);
    table
}
