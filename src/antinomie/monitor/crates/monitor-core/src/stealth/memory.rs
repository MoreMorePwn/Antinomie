// SPDX-License-Identifier: GPL-3.0-only
//! The memory array (SMBIOS type 16) and its devices (type 17), written whole
//! as a PC's firmware does, for modules whose sizes add up to the VM's RAM:
//! the parts a real unit of the machine shipped with, in a sensible number.
use super::parts::RamPart;
use super::{MACHINES, MachineIdentity, smbios};

/// The handle of the memory array (QEMU's) and of the first memory device.
const MEMORY_ARRAY_HANDLE: u16 = 0x1000;
const MEMORY_DEVICE_HANDLE: u16 = 0x1100;

/// The largest module QEMU counts in its own array.
const QEMU_MODULE_MIB: u64 = 16 * 1024;

/// One memory module as its firmware reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Module {
    pub size_mib: u64,
    pub manufacturer: String,
    pub part: String,
    pub memory_type: u8,
    pub speed: u16,
    pub rank: u8,
    pub form: u8,
    pub width: u16,
}

impl Module {
    fn of_part(part: &RamPart, size_mib: u64) -> Self {
        Self {
            size_mib,
            manufacturer: part.manufacturer.into(),
            part: part.part.into(),
            memory_type: part.memory_type,
            speed: part.speed,
            rank: part.rank,
            form: part.form,
            width: part.width,
        }
    }
}

/// The module to use for `size_mib`: `current`'s own part when it has that
/// size, else one of the same maker, else the first listed of that size.
fn part_of_size<'a>(
    parts: &[&'a RamPart],
    current: &RamPart,
    size_mib: u64,
) -> Option<&'a RamPart> {
    let of_size = |part: &&&RamPart| u64::from(part.size_mib) == size_mib;
    parts
        .iter()
        .filter(of_size)
        .find(|part| part.part == current.part && part.manufacturer == current.manufacturer)
        .or_else(|| {
            parts
                .iter()
                .filter(of_size)
                .find(|part| part.manufacturer == current.manufacturer)
        })
        .or_else(|| parts.iter().find(of_size))
        .copied()
}

/// `count` module sizes from `sizes` (largest first) adding up to `rest`,
/// the sizes never increasing.
fn exact_mix(rest: u64, sizes: &[u64], count: usize, out: &mut Vec<u64>) -> bool {
    if count == 0 {
        return rest == 0;
    }
    for (index, size) in sizes.iter().enumerate() {
        if *size <= rest {
            out.push(*size);
            if exact_mix(rest - size, &sizes[index..], count - 1, out) {
                return true;
            }
            out.pop();
        }
    }
    false
}

/// The fewest modules (up to `slots`) of sizes from `sizes` that add up to
/// `total`.
fn size_mix(total: u64, sizes: &[u64], slots: usize) -> Option<Vec<u64>> {
    (1..=slots).find_map(|count| {
        let mut out = Vec::new();
        exact_mix(total, sizes, count, &mut out).then_some(out)
    })
}

/// The modules for `ram_mib`: the identity's machine's parts, when the
/// identity's own part is one of them, in one or two equal modules (a single
/// one for up to 8 GiB), else two or more of different sizes that add up;
/// the identity's strings in modules of up to 16 GiB (QEMU's count) when the
/// machine or part is not in the catalog (an edited identity) or no mix of
/// its parts fits.
pub(super) fn module_plan(id: &MachineIdentity, ram_mib: u64) -> Vec<Module> {
    catalog_plan(id, ram_mib).unwrap_or_else(|| legacy_plan(id, ram_mib))
}

fn catalog_plan(id: &MachineIdentity, ram_mib: u64) -> Option<Vec<Module>> {
    let machine = MACHINES.iter().find(|machine| machine.id == id.profile);
    let current = machine.and_then(|machine| {
        machine
            .memory
            .iter()
            .find(|part| part.part == id.memory_part && part.manufacturer == id.memory_manufacturer)
    });
    if let (Some(machine), Some(current)) = (machine, current) {
        let compatible: Vec<&RamPart> = machine
            .memory
            .iter()
            .filter(|part| {
                part.memory_type == current.memory_type
                    && part.form == current.form
                    && part.width == current.width
            })
            .collect();
        let slots = id.memory_slots.len().clamp(1, 4);
        let order: &[u64] = if ram_mib <= 8 * 1024 {
            &[1, 2, 4]
        } else {
            &[2, 1, 4]
        };
        for count in order {
            if *count as usize <= slots
                && ram_mib.is_multiple_of(*count)
                && let Some(part) = part_of_size(&compatible, current, ram_mib / count)
            {
                return Some(
                    (0..*count)
                        .map(|_| Module::of_part(part, ram_mib / count))
                        .collect(),
                );
            }
        }
        let mut sizes: Vec<u64> = compatible
            .iter()
            .map(|part| u64::from(part.size_mib))
            .collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        sizes.dedup();
        if let Some(mix) = size_mix(ram_mib, &sizes, slots) {
            return Some(
                mix.into_iter()
                    .filter_map(|size| {
                        part_of_size(&compatible, current, size)
                            .map(|part| Module::of_part(part, size))
                    })
                    .collect(),
            );
        }
        // No mix adds up: the largest parts that fit, and the rest in a
        // last module (the smallest part, as a module of an odd size).
        let mut rest = ram_mib;
        let mut modules = Vec::new();
        while rest > 0 {
            let last = modules.len() + 1 == slots;
            let size = sizes
                .iter()
                .copied()
                .find(|size| *size <= rest)
                .filter(|_| !last);
            let (part, size) = match size {
                Some(size) => (part_of_size(&compatible, current, size)?, size),
                None if rest <= *sizes.first()? => {
                    let fitting = sizes.iter().copied().find(|size| *size == rest);
                    let size_for_part = fitting.unwrap_or(*sizes.last()?);
                    (part_of_size(&compatible, current, size_for_part)?, rest)
                }
                None => return None,
            };
            modules.push(Module::of_part(part, size));
            rest -= size;
        }
        return Some(modules);
    }
    None
}

fn legacy_plan(id: &MachineIdentity, ram_mib: u64) -> Vec<Module> {
    let count = ram_mib.div_ceil(QEMU_MODULE_MIB).max(1);
    let (kind, speed) = (
        if id.memory_type == 0 {
            0x1a
        } else {
            id.memory_type
        },
        if id.memory_speed == 0 {
            3200
        } else {
            id.memory_speed
        },
    );
    (0..count)
        .map(|index| Module {
            size_mib: if index + 1 < count {
                QEMU_MODULE_MIB
            } else {
                ram_mib - QEMU_MODULE_MIB * (count - 1)
            },
            manufacturer: id.memory_manufacturer.clone(),
            part: id.memory_part.clone(),
            memory_type: kind,
            speed,
            rank: id.memory_rank,
            form: id.memory_form,
            width: id.memory_width,
        })
        .collect()
}

/// The largest memory the machine's array could hold: all its slots with the
/// largest compatible module of the catalog, never less than `ram_mib`.
fn array_capacity_mib(id: &MachineIdentity, modules: &[Module], ram_mib: u64) -> u64 {
    let machine = MACHINES.iter().find(|machine| machine.id == id.profile);
    let biggest = machine
        .into_iter()
        .flat_map(|machine| machine.memory.iter())
        .filter(|part| modules.first().is_none_or(|first| part.form == first.form))
        .map(|part| u64::from(part.size_mib))
        .max()
        .unwrap_or(0);
    let slots = id.memory_slots.len().max(modules.len()).max(1) as u64;
    (slots * biggest).max(ram_mib).next_multiple_of(1024)
}

/// SMBIOS type 16 (physical memory array): the system board's memory, with
/// the modules' count and the capacity of its slots, in place of QEMU's
/// array of 16 GiB modules.
pub(super) fn array_table(id: &MachineIdentity, ram_mib: u64, ecc: bool) -> Vec<u8> {
    let modules = module_plan(id, ram_mib);
    let capacity_kib = array_capacity_mib(id, &modules, ram_mib) * 1024;
    let (numbers, strings) = smbios::string_set(&[]);
    debug_assert!(numbers.is_empty());
    let mut table = vec![16, 0x17];
    table.extend(MEMORY_ARRAY_HANDLE.to_le_bytes());
    // System board, system memory, and its error correction.
    table.extend([3, 3, if ecc { 6 } else { 3 }]);
    match u32::try_from(capacity_kib) {
        Ok(kib) if kib < 0x8000_0000 => table.extend(kib.to_le_bytes()),
        _ => table.extend(0x8000_0000u32.to_le_bytes()),
    }
    table.extend(0xfffeu16.to_le_bytes()); // no error information
    table.extend((modules.len().max(id.memory_slots.len()) as u16).to_le_bytes());
    table.extend((capacity_kib * 1024).to_le_bytes());
    table.extend(strings);
    table
}

/// SMBIOS type 17 (memory device) structures for `ram_mib` of memory, one
/// per [`module_plan`] module, each in the next of the identity's slots:
/// what a PC's firmware writes for the module (its type, speed, rank and
/// width), in place of QEMU's "RAM" of unknown width in "DIMM 0". The slots
/// the modules leave are empty devices, as a PC's.
pub(super) fn memory_tables(id: &MachineIdentity, ram_mib: u64, ecc: bool) -> Vec<Vec<u8>> {
    let modules = module_plan(id, ram_mib);
    let mut tables: Vec<Vec<u8>> = modules
        .iter()
        .enumerate()
        .map(|(index, module)| memory_table(id, index, Some(module), ecc))
        .collect();
    for index in modules.len()..id.memory_slots.len().min(4) {
        tables.push(memory_table(id, index, None, ecc));
    }
    tables
}

fn memory_table(id: &MachineIdentity, index: usize, module: Option<&Module>, ecc: bool) -> Vec<u8> {
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
    let handle = MEMORY_DEVICE_HANDLE + index as u16;
    let Some(module) = module else {
        // An empty slot: size 0, everything else unknown.
        let (numbers, strings) = smbios::string_set(&[&locator, &bank, "", "", "", ""]);
        let mut table = vec![17, 0x28];
        table.extend(handle.to_le_bytes());
        table.extend(MEMORY_ARRAY_HANDLE.to_le_bytes());
        table.extend(0xfffeu16.to_le_bytes());
        table.extend([0xff, 0xff, 0xff, 0xff]); // widths unknown
        table.extend(0u16.to_le_bytes()); // no module installed
        table.extend([2, 0, numbers[0], numbers[1], 2]); // unknown form and type
        table.extend(0x0004u16.to_le_bytes()); // type detail: unknown
        table.extend(0u16.to_le_bytes());
        table.extend([numbers[2], numbers[3], numbers[4], numbers[5], 0]);
        table.extend(0u32.to_le_bytes());
        table.extend(0u16.to_le_bytes());
        table.extend([0; 6]);
        table.extend(strings);
        return table;
    };
    let (numbers, strings) = smbios::string_set(&[
        &locator,
        &bank,
        &module.manufacturer,
        &serial,
        "",
        &module.part,
    ]);
    let (size, extended) = match u16::try_from(module.size_mib) {
        Ok(size) if size < 0x7fff => (size, 0u32),
        _ => (0x7fff, u32::try_from(module.size_mib).unwrap_or(u32::MAX)),
    };
    // An identity saved before 0.8.0 recorded none of these: 64 bits (72
    // with ECC).
    let total_width = if module.width == 0 {
        if ecc { 72 } else { 64 }
    } else {
        module.width
    };
    let data_width = if total_width == 72 { 64 } else { total_width };
    // Millivolts: LPDDR5 runs at 0.5 V, DDR5 at 1.1 V, DDR4 at 1.2 V.
    let voltage: u16 = match module.memory_type {
        0x23 => 500,
        0x22 => 1100,
        _ => 1200,
    };
    let mut table = vec![17, 0x28];
    table.extend(handle.to_le_bytes());
    table.extend(MEMORY_ARRAY_HANDLE.to_le_bytes()); // QEMU's type 16 array
    table.extend(0xfffeu16.to_le_bytes()); // no error information
    table.extend(total_width.to_le_bytes());
    table.extend(data_width.to_le_bytes());
    table.extend(size.to_le_bytes()); // MiB
    table.extend([
        module.form.max(1),
        0,
        numbers[0],
        numbers[1],
        module.memory_type,
    ]);
    table.extend(id.memory_detail.to_le_bytes());
    table.extend(module.speed.to_le_bytes());
    table.extend([
        numbers[2],
        numbers[3],
        numbers[4],
        numbers[5],
        module.rank.clamp(1, 15),
    ]);
    table.extend(extended.to_le_bytes());
    table.extend(module.speed.to_le_bytes()); // configured speed
    for _ in 0..3 {
        table.extend(voltage.to_le_bytes()); // minimum, maximum, configured
    }
    table.extend(strings);
    table
}
