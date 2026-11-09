// SPDX-License-Identifier: GPL-3.0-only
//! The device profile of an arm64 VM (MA-17). The x86 catalog's machines are
//! PCs; an arm64 VM booting through UEFI presents an arm64 machine of the
//! profile's kind instead (an Ampere Altra server or workstation, an AWS
//! Graviton2 instance), the same one for the VM's life (picked by its UUID):
//! its CPU (QEMU model, MIDR, timer frequency), SMBIOS tables, ACPI OEM IDs,
//! network card and MAC prefix, and SATA disk. One identity everywhere:
//! /proc/cpuinfo's CPU part, the firmware's processor and DMI name the same
//! machine, and no value is the host's.
use super::{
    ARM_MACHINES, ArmKind, ArmMachine, BoardTree, DiskBus, MachineIdentity, MemorySlot, NicSlot,
    StealthPreset, StealthProfile, fdt, launch::escape, memory, processor, smbios,
};
use std::{path::Path, process::Command};

/// The arm64 machine `profile` presents, or None for QEMU's own identity
/// (Transparent, or the identity turned off).
pub fn arm_machine(profile: &StealthProfile) -> Option<&'static ArmMachine> {
    if !profile.identity_enabled || profile.preset == StealthPreset::Transparent {
        return None;
    }
    if let Some(machine) = ArmMachine::find(&profile.identity.profile) {
        return Some(machine);
    }
    let kind = match profile.preset {
        StealthPreset::CloudVps => ArmKind::Cloud,
        StealthPreset::RealisticServer => ArmKind::Server,
        // A desktop without UEFI: a single-board computer on its device tree.
        _ if !profile.firmware.is_uefi() => ArmKind::Board,
        _ => ArmKind::Workstation,
    };
    of_kind(kind, &profile.identity.system_uuid)
}

/// The machine of `kind` for the VM of `uuid`.
fn of_kind(kind: ArmKind, uuid: &str) -> Option<&'static ArmMachine> {
    let choices: Vec<&ArmMachine> = ARM_MACHINES
        .iter()
        .filter(|machine| machine.kind == kind)
        .collect();
    let index = uuid_number(uuid) as usize % choices.len().max(1);
    choices.get(index).copied()
}

/// The board `profile` presents when its UEFI machine cannot boot (no AAVMF,
/// or a base without UEFI support): the VM boots on a board's device tree.
pub fn board_for(profile: &StealthProfile) -> Option<&'static ArmMachine> {
    arm_machine(profile).and(of_kind(ArmKind::Board, &profile.identity.system_uuid))
}

/// A number from the UUID's hex digits, stable for a VM.
fn uuid_number(uuid: &str) -> u64 {
    uuid.chars()
        .filter_map(|c| c.to_digit(16))
        .fold(0u64, |sum, digit| {
            sum.wrapping_mul(16).wrapping_add(u64::from(digit))
        })
}

/// `template` with `#` as digits and `@` as capital letters from `uuid`.
fn serial(template: &str, uuid: &str) -> String {
    let mut number = uuid_number(uuid);
    template
        .chars()
        .map(|c| {
            let (base, first) = match c {
                '#' => (10, b'0'),
                '@' => (26, b'A'),
                other => return other,
            };
            let value = (number % base) as u8;
            number = (number / base) ^ 0x9e37_79b9_7f4a_7c15;
            char::from(first + value)
        })
        .collect()
}

/// The identity of `machine` for a VM of `cpus` vCPUs and `ram_mib`, with
/// the VM's own UUID (a cloud's: "ec2" first, as EC2 numbers instances).
pub fn identity(
    machine: &ArmMachine,
    base: &MachineIdentity,
    cpus: u16,
    ram_mib: u32,
) -> MachineIdentity {
    let mut uuid = base.system_uuid.clone();
    if machine.kind == ArmKind::Cloud && uuid.len() > 3 {
        uuid.replace_range(..3, "ec2");
    }
    let product = machine
        .plan_for(cpus, ram_mib)
        .map_or(machine.system.1, |plan| plan.name);
    let system_serial = if machine.serial.is_empty() {
        uuid.clone()
    } else {
        serial(machine.serial, &uuid)
    };
    let (memory_manufacturer, memory_part, memory_speed, locator, ecc) = machine.memory;
    MachineIdentity {
        profile: machine.id.into(),
        bios_vendor: machine.bios.0.into(),
        bios_version: machine.bios.1.into(),
        bios_date: machine.bios.2.into(),
        virtual_machine: machine.virtual_machine,
        system_manufacturer: machine.system.0.into(),
        system_product: product.into(),
        system_version: machine.system.2.into(),
        system_family: machine.system.3.into(),
        system_sku: machine.system.4.into(),
        board_serial: if machine.board.1.is_empty() {
            String::new()
        } else {
            serial("##########", &format!("{uuid}b"))
        },
        system_serial,
        system_uuid: uuid,
        board_manufacturer: machine.board.0.into(),
        board_product: machine.board.1.into(),
        board_version: machine.board.2.into(),
        chassis_manufacturer: machine.chassis.0.into(),
        chassis_type: machine.chassis.1,
        chassis_version: machine.chassis.2.into(),
        cpu_manufacturer: machine.cpu_manufacturer.into(),
        cpu_version: machine.cpu_version.into(),
        cpu_socket: machine.cpu_socket.into(),
        memory_manufacturer: memory_manufacturer.into(),
        memory_part: memory_part.into(),
        memory_slots: vec![MemorySlot {
            locator: locator.into(),
            bank: String::new(),
        }],
        memory_form: 9,
        // Registered ECC DIMMs, else synchronous ones.
        memory_detail: if ecc { 0x2080 } else { 0x0080 },
        memory_type: 0x1a,
        memory_speed,
        memory_rank: 2,
        memory_width: if ecc { 72 } else { 64 },
        acpi_oem_id: machine.acpi.0.into(),
        acpi_table_id: machine.acpi.1.into(),
        disk_model: machine.disk.0.into(),
        disk_firmware: machine.disk.1.into(),
        disk_serial: serial("S4##@#######", &format!("{}d", base.system_uuid)),
        disk_rotation: 1,
        ..MachineIdentity::default()
    }
}

/// `profile` as `machine` presents it: its identity, a SATA disk (QEMU's
/// NVMe controller names itself QEMU) and its MAC prefix.
pub fn arm_profile(
    profile: &StealthProfile,
    machine: &ArmMachine,
    cpus: u16,
    ram_mib: u32,
) -> StealthProfile {
    let mut arm = profile.clone();
    arm.identity = identity(machine, &profile.identity, cpus, ram_mib);
    arm.disk_bus = DiskBus::Sata;
    let tail = uuid_number(&format!("{}m", profile.identity.system_uuid)).to_be_bytes();
    let prefix = machine
        .mac_prefix
        .unwrap_or([0x02 | (tail[0] & 0xfc), tail[1], tail[2]]);
    arm.mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        prefix[0], prefix[1], prefix[2], tail[5], tail[6], tail[7]
    );
    arm
}

/// The machine an arm64 VM of `profile` presents when it boots UEFI
/// (`uefi`: its base supports it and the host has AAVMF) or not: a UEFI
/// machine without UEFI is shown as a board on its device tree.
pub fn presented(profile: &StealthProfile, uefi: bool) -> Option<&'static ArmMachine> {
    match arm_machine(profile) {
        Some(machine) if machine.tree.is_none() && !uefi => board_for(profile),
        machine => machine,
    }
}

impl ArmKind {
    /// The kind as the Device profile window names it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Workstation => "workstation",
            Self::Cloud => "cloud instance",
            Self::Board => "single-board computer",
        }
    }
}

/// The profile a VM on a base of `arch` with `stealth_support` shows: on
/// arm64 with a base that boots UEFI, the arm64 machine's (a run's record
/// and the VM's summary name it).
pub fn shown_profile(
    profile: &StealthProfile,
    arch: crate::api::GuestArch,
    stealth_support: &[String],
    cpus: u16,
    ram_mib: u32,
) -> StealthProfile {
    let uefi = super::BaseSupport::from_list(stealth_support).uefi;
    match presented(profile, uefi) {
        Some(machine) if arch == crate::api::GuestArch::AARCH64 => {
            arm_profile(profile, machine, cpus, ram_mib)
        }
        _ => profile.clone(),
    }
}

/// The `-cpu` value: the machine's core with its MIDR and timer frequency.
pub fn cpu_option(machine: &ArmMachine) -> String {
    format!(
        "{},midr=0x{:x},cntfrq={}",
        machine.cpu, machine.midr, machine.cntfrq_hz
    )
}

/// Extra `virt` machine properties: the ACPI tables' OEM IDs.
pub fn machine_options(identity: &MachineIdentity) -> String {
    format!(
        ",x-oem-id={},x-oem-table-id={}",
        escape(&identity.acpi_oem_id),
        escape(&identity.acpi_table_id)
    )
}

/// The network card: Intel's 82576 (driver igb, as the I210 and I350 of
/// Altra boards), with the profile's MAC.
pub fn nic_option(profile: &StealthProfile) -> String {
    format!("igb,netdev=net0,mac={}", profile.mac)
}

/// QEMU's igb (hw/net/igb.c): eight SR-IOV virtual functions, the first at
/// the card's own device and function number plus 0x80, the others two apart.
const IGB_VF_OFFSET: u16 = 0x80;
const IGB_VF_STRIDE: u16 = 2;
const IGB_VFS: u16 = 8;

/// Whether QEMU can put its igb at `slot`: its last virtual function must
/// stay on bus 0 (function 0xff at most), or QEMU exits with "VF addr
/// overflows" before the VM starts.
pub fn igb_fits(slot: NicSlot) -> bool {
    slot.devfn() + IGB_VF_OFFSET + IGB_VF_STRIDE * (IGB_VFS - 1) <= 0xff
}

/// The `-device` value of an arm64 VM's network card, and a note when it is
/// not the one the profile asks for. `machine`: the VM presents an arm64
/// machine, whose card is [`nic_option`]'s igb; otherwise (Transparent) the
/// profile's own model. `slot`: where a base that names its NIC by slot has
/// it ([`NicSlot::Virt`] since 0.9.0); none: QEMU picks the first free slot,
/// where the igb fits. A disk provisioned for 00:19.0 before keeps that place
/// (its network configuration names the interface udev gives it there) with
/// the profile's model, which has no virtual functions.
pub fn nic_device(
    profile: &StealthProfile,
    machine: bool,
    slot: Option<NicSlot>,
) -> (String, Option<String>) {
    match slot {
        _ if !machine => (super::nic_option_for(profile, slot), None),
        Some(slot) if !igb_fits(slot) => (
            super::nic_option_for(profile, Some(slot)),
            Some(format!(
                "This VM's disk configures its network card at {}, where QEMU's igb (the arm64 \
                 machine's Intel 82576) does not fit (its SR-IOV functions would pass the bus's \
                 last address); the card there is QEMU's {}. A VM created again gets the igb \
                 at {}.",
                slot.label(),
                profile.nic.device(),
                NicSlot::Virt.label()
            )),
        ),
        Some(slot) => (format!("{},{}", nic_option(profile), slot.address()), None),
        None => (nic_option(profile), None),
    }
}

/// Neoverse N1's caches per core: 64 KiB L1 instruction and data, 1 MiB L2.
fn n1_caches() -> Vec<processor::Cache> {
    [(1, 3, 64, 4), (1, 4, 64, 4), (2, 5, 1024, 8)]
        .into_iter()
        .map(|(level, kind, kib, ways)| processor::Cache {
            level,
            kind,
            kib,
            ways,
        })
        .collect()
}

/// The SMBIOS tables of `profile` (an [`arm_profile`]) for UEFI: written
/// whole into `runtime_dir` (BIOS, chassis, processor, memory) or as QEMU's
/// type 1 and 2 options, so no field keeps QEMU's value.
pub fn apply(
    command: &mut Command,
    profile: &StealthProfile,
    machine: &ArmMachine,
    runtime_dir: &Path,
    ram_mib: u32,
    cpus: u16,
) -> Result<(), String> {
    let id = &profile.identity;
    let given = |name: &str, value: &str| format!(",{name}={}", escape(value));
    let field = |name: &str, value: &str| {
        if value.is_empty() {
            String::new()
        } else {
            given(name, value)
        }
    };
    let write_table = |name: &str, table: Vec<u8>| -> Result<String, String> {
        let path = runtime_dir.join(name);
        std::fs::write(&path, table).map_err(|error| format!("SMBIOS {name}: {error}"))?;
        Ok(format!("file={}", escape(&path.to_string_lossy())))
    };
    command.arg("-smbios").arg(write_table(
        "smbios-bios.bin",
        smbios::bios_table(id, true),
    )?);
    command.arg("-smbios").arg(format!(
        "type=1{}{}{}{}{}{}{}",
        given("manufacturer", &id.system_manufacturer),
        given("product", &id.system_product),
        given("version", &id.system_version),
        field("serial", &id.system_serial),
        field("uuid", &id.system_uuid),
        field("sku", &id.system_sku),
        field("family", &id.system_family)
    ));
    command.arg("-smbios").arg(format!(
        "type=2{}{}{}{}",
        given("manufacturer", &id.board_manufacturer),
        given("product", &id.board_product),
        given("version", &id.board_version),
        field("serial", &id.board_serial)
    ));
    let cores = cpus.max(1);
    let processor = processor::Processor {
        socket: id.cpu_socket.clone(),
        manufacturer: id.cpu_manufacturer.clone(),
        brand: id.cpu_version.clone(),
        part: String::new(),
        // An Arm CPU's processor ID is its MIDR_EL1 (and no SoC ID).
        signature: (machine.midr, 0),
        // ARMv8.
        family: 0x0101,
        max_mhz: machine.cpu_mhz,
        current_mhz: machine.cpu_mhz,
        // Upgrade: none (a soldered or LGA socket the table does not name).
        upgrade: 0x06,
        voltage: 0,
        cores,
        threads: cores,
        // 64-bit capable, multi-core, execute protection, enhanced
        // virtualisation, power/performance control.
        characteristics: 0x00ec,
        caches: n1_caches(),
    };
    for (index, table) in processor.tables().into_iter().enumerate() {
        let file = write_table(&format!("smbios-processor-{index}.bin"), table)?;
        command.arg("-smbios").arg(file);
    }
    let ecc = id.memory_detail & 0x2000 != 0;
    let array = write_table(
        "smbios-memory-array.bin",
        memory::array_table(id, u64::from(ram_mib), ecc),
    )?;
    command.arg("-smbios").arg(array);
    for (index, table) in memory::memory_tables(id, u64::from(ram_mib), ecc)
        .into_iter()
        .enumerate()
    {
        let file = write_table(&format!("smbios-memory-{index}.bin"), table)?;
        command.arg("-smbios").arg(file);
    }
    let chassis = write_table("smbios-chassis.bin", smbios::chassis_table(id))?;
    command.arg("-smbios").arg(chassis);
    Ok(())
}

/// The serial number a board's firmware writes into the tree: the board's
/// prefix, then hex digits from the VM's UUID (16 in all).
fn board_serial(tree: &BoardTree, uuid: &str) -> String {
    let digits: String = uuid
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let mut serial = tree.serial_prefix.to_owned();
    serial.push_str(&digits[..digits.len().min(16 - serial.len().min(16))]);
    serial
}

/// QEMU's `virt` device tree as `machine`'s board: its model, compatible
/// list and serial number at the root; virt's QEMU-only nodes (fw_cfg,
/// virtio-mmio slots, the platform bus, flash, GPIO power key) taken out;
/// the PL011 and PL031 named as a board's tree names them.
pub fn disguise_tree(tree: &mut fdt::Fdt, board: &BoardTree, uuid: &str) {
    let root = &mut tree.root;
    root.set("model", fdt::strings(&[board.model]));
    root.set("compatible", fdt::strings(board.compatible));
    root.set("serial-number", fdt::strings(&[&board_serial(board, uuid)]));
    let qemu_only = |node: &fdt::Node| {
        [
            "fw-cfg@",
            "virtio_mmio@",
            "platform-bus@",
            "platform@",
            "flash@",
            "pl061@",
            "gpio-keys",
        ]
        .iter()
        .any(|prefix| node.name.starts_with(prefix))
            || node
                .prop("compatible")
                .is_some_and(|value| value.windows(5).any(|window| window == b"qemu,"))
    };
    root.children.retain(|node| !qemu_only(node));
    add_caches(tree, board);
    let root = &mut tree.root;
    let renames = [
        ("pl011@", "serial@"),
        ("pl031@", "rtc@"),
        ("intc@", "interrupt-controller@"),
    ];
    for node in &mut root.children {
        for (from, to) in renames {
            if let Some(rest) = node.name.strip_prefix(from) {
                node.name = format!("{to}{rest}");
            }
        }
    }
    // Paths to renamed nodes (stdout-path, aliases).
    for name in ["chosen", "aliases"] {
        if let Some(node) = root.child_mut(name) {
            for (_, value) in &mut node.props {
                let mut text = String::from_utf8_lossy(value).into_owned();
                for (from, to) in renames {
                    text = text.replace(&format!("/{from}"), &format!("/{to}"));
                }
                *value = text.into_bytes();
            }
        }
    }
}

/// The highest phandle in `node` and below it.
fn max_phandle(node: &fdt::Node) -> u32 {
    let own = node
        .prop("phandle")
        .and_then(|value| value.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    node.children.iter().map(max_phandle).fold(own, u32::max)
}

/// A cache node of `level`, `(bytes, ways)`, 64-byte lines.
fn cache_node(
    name: &str,
    level: u32,
    (bytes, ways): (u32, u32),
    phandle: u32,
    next: Option<u32>,
) -> fdt::Node {
    let cell = |value: u32| value.to_be_bytes().to_vec();
    let mut props = vec![
        ("compatible".to_owned(), fdt::strings(&["cache"])),
        ("cache-unified".to_owned(), Vec::new()),
        ("cache-size".to_owned(), cell(bytes)),
        ("cache-line-size".to_owned(), cell(64)),
        ("cache-sets".to_owned(), cell(bytes / 64 / ways.max(1))),
        ("cache-level".to_owned(), cell(level)),
    ];
    if let Some(next) = next {
        props.push(("next-level-cache".to_owned(), cell(next)));
    }
    props.push(("phandle".to_owned(), cell(phandle)));
    fdt::Node {
        name: name.into(),
        props,
        children: Vec::new(),
    }
}

/// The board's caches in its CPU nodes, as its own tree has them (QEMU's
/// describes none, so the kernel would list no cache sizes).
fn add_caches(tree: &mut fdt::Fdt, board: &BoardTree) {
    let mut next = max_phandle(&tree.root) + 1;
    let Some(cpus) = tree.root.child_mut("cpus") else {
        return;
    };
    let mut take = || {
        next += 1;
        next - 1
    };
    let l3 = (board.l3.0 > 0).then(|| {
        let phandle = take();
        cpus.children
            .push(cache_node("l3-cache", 3, board.l3, phandle, None));
        phandle
    });
    let (l2_bytes, l2_ways, per_core) = board.l2;
    let shared = (!per_core).then(|| {
        let phandle = take();
        cpus.children
            .push(cache_node("l2-cache0", 2, (l2_bytes, l2_ways), phandle, l3));
        phandle
    });
    let cell = |value: u32| value.to_be_bytes().to_vec();
    for cpu in cpus
        .children
        .iter_mut()
        .filter(|node| node.name.starts_with("cpu@"))
    {
        for (prefix, (bytes, ways)) in [("i", board.l1i), ("d", board.l1d)] {
            cpu.set(&format!("{prefix}-cache-size"), cell(bytes));
            cpu.set(&format!("{prefix}-cache-line-size"), cell(64));
            cpu.set(
                &format!("{prefix}-cache-sets"),
                cell(bytes / 64 / ways.max(1)),
            );
        }
        let l2 = shared.unwrap_or_else(|| {
            let phandle = take();
            cpu.children
                .push(cache_node("l2-cache", 2, (l2_bytes, l2_ways), phandle, l3));
            phandle
        });
        cpu.set("next-level-cache", cell(l2));
    }
}

/// Writes `machine`'s board tree to `out`: QEMU's own tree of the same
/// machine, CPUs and memory (`dumpdtb`), disguised.
pub fn board_dtb(
    qemu: &Path,
    machine: &ArmMachine,
    cpus: u16,
    ram_mib: u32,
    uuid: &str,
    out: &Path,
) -> Result<(), String> {
    let board = machine.tree.as_ref().ok_or("not a board")?;
    let dump = out.with_extension("virt.dtb");
    let path = dump.to_str().ok_or("the runtime folder is not UTF-8")?;
    let result = Command::new(qemu)
        .arg("-machine")
        .arg(format!("virt,gic-version=3,dumpdtb={}", escape(path)))
        .args(["-cpu", &cpu_option(machine), "-smp", &cpus.to_string()])
        .args([
            "-m",
            &ram_mib.to_string(),
            "-accel",
            "tcg",
            "-nodefaults",
            "-display",
            "none",
        ])
        .output()
        .map_err(|error| format!("QEMU's device tree: {error}"))?;
    let data = std::fs::read(&dump).map_err(|error| {
        format!(
            "QEMU's device tree: {error} ({})",
            String::from_utf8_lossy(&result.stderr).trim()
        )
    })?;
    let _ = std::fs::remove_file(&dump);
    let mut tree = fdt::Fdt::parse(&data)?;
    disguise_tree(&mut tree, board, uuid);
    std::fs::write(out, tree.to_bytes()).map_err(|error| format!("board device tree: {error}"))
}

/// What still tells an arm64 VM apart, most telling first. `machine`: the
/// arm64 machine it presents (UEFI boots), else QEMU's own identity.
pub fn giveaways(
    machine: Option<&ArmMachine>,
    uefi: bool,
    fast_emulation: bool,
) -> Vec<&'static str> {
    let mut found = vec!["instruction timing of an emulated CPU (TCG, no hardware virtualisation)"];
    match machine {
        Some(machine) if machine.tree.is_some() => {
            found.extend([
                "the virt machine's devices in the device tree: GICv3, the generic ECAM PCIe \
                 host and an armv8 timer, not the board's BCM2711/BCM2712 peripherals",
                "the network card is Intel's 82576 on PCIe and the disk SATA on AHCI, not the \
                 board's Ethernet and SD card or USB disk",
            ]);
        }
        Some(machine) => {
            found.push(
                "QEMU's ACPI tables to root: the BXPC creator ID (also in the kernel log's \
                 table list) and virt's devices in the DSDT",
            );
            found.push(match machine.kind {
                ArmKind::Cloud => {
                    "the network card is Intel's 82576 and the disk SATA, not the \
                     instance's ENA and NVMe (EBS)"
                }
                _ => "the network card is Intel's 82576 (driver igb), not the board's own chip",
            });
            found.extend([
                "the SATA controller is Intel's ICH9 AHCI, which no arm64 board has",
                "no CPU cache sizes in sysfs: QEMU's PPTT describes no caches",
                "AAVMF's vendor string (the host distribution's EDK II), to root",
            ]);
        }
        None if uefi => {
            found.push("QEMU in the SMBIOS and ACPI tables (QEMU, BOCHS/BXPC), chassis type Other")
        }
        None => found.push("QEMU's device tree: linux,dummy-virt and the virt machine's nodes"),
    }
    found.push("the virt machine's PCIe host bridge (Red Hat vendor ID)");
    if fast_emulation {
        found.push(
            "faster emulation: no kernel page-table isolation (KPTI), which a real \
             machine of this CPU with KASLR has",
        );
    }
    found.extend([
        "the emulated display (virtio-gpu)",
        "a fresh boot: minutes of uptime",
    ]);
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(preset: StealthPreset) -> StealthProfile {
        let mut profile = StealthProfile::realistic(StealthPreset::RealisticServer, "GenuineIntel");
        profile.preset = preset;
        profile.identity.system_uuid = "4c4c4544-0042-3510-8051-b4c04f4e4a32".into();
        profile
    }

    #[test]
    fn each_preset_presents_an_arm64_machine_of_its_kind() {
        let kind = |preset| arm_machine(&profile(preset)).map(|machine| machine.kind);
        assert_eq!(kind(StealthPreset::RealisticServer), Some(ArmKind::Server));
        assert_eq!(
            kind(StealthPreset::RealisticDesktop),
            Some(ArmKind::Workstation)
        );
        assert_eq!(
            kind(StealthPreset::RealisticLaptop),
            Some(ArmKind::Workstation)
        );
        assert_eq!(kind(StealthPreset::CloudVps), Some(ArmKind::Cloud));
        assert_eq!(kind(StealthPreset::Transparent), None);
        let mut off = profile(StealthPreset::RealisticServer);
        off.identity_enabled = false;
        assert!(arm_machine(&off).is_none());
        // The same VM keeps its machine; a pinned one is kept.
        let server = profile(StealthPreset::RealisticServer);
        assert_eq!(arm_machine(&server), arm_machine(&server.clone()));
        let mut pinned = profile(StealthPreset::RealisticServer);
        pinned.identity.profile = "arm-hpe-rl300-gen11".into();
        assert_eq!(arm_machine(&pinned).unwrap().id, "arm-hpe-rl300-gen11");
    }

    #[test]
    fn the_identity_names_one_machine_and_nothing_of_the_host_or_qemu() {
        for machine in ARM_MACHINES {
            let arm = arm_profile(&profile(StealthPreset::RealisticServer), machine, 2, 1024);
            let id = &arm.identity;
            let all = format!("{id:?}").to_lowercase();
            for word in [
                "qemu",
                "bochs",
                "bxpc",
                "kvm",
                "intel",
                "amd",
                "standard pc",
            ] {
                assert!(!all.contains(word), "{} has {word}", machine.id);
            }
            assert_eq!(id.profile, machine.id);
            assert_eq!(id.cpu_version, machine.cpu_version);
            assert!(id.acpi_oem_id.len() <= 6 && id.acpi_table_id.len() <= 8);
            assert!(!id.system_serial.contains(['#', '@']));
            assert_eq!(arm.disk_bus, DiskBus::Sata);
            assert_eq!(arm.mac.len(), 17);
            if let Some(prefix) = machine.mac_prefix {
                assert!(arm.mac.starts_with(&format!("{:02x}:", prefix[0])));
            } else {
                // Locally administered, unicast.
                let first = u8::from_str_radix(&arm.mac[..2], 16).unwrap();
                assert_eq!(first & 0x03, 0x02);
            }
            if machine.tree.is_none() {
                assert!(cpu_option(machine).starts_with("neoverse-n1,midr=0x413fd0c1,cntfrq="));
            }
        }
        let aws = ArmMachine::find("arm-aws-graviton2").unwrap();
        let id = identity(aws, &profile(StealthPreset::CloudVps).identity, 2, 2048);
        assert!(id.system_uuid.starts_with("ec2") && id.system_serial == id.system_uuid);
        assert_eq!(id.system_product, "t4g.small");
        assert!(id.virtual_machine);
    }

    #[test]
    fn uefi_launch_writes_every_table_qemu_would_fill() {
        let dir = std::env::temp_dir().join(format!("ant-arm64-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let machine = ArmMachine::find("arm-gigabyte-r272-p33").unwrap();
        let arm = arm_profile(&profile(StealthPreset::RealisticServer), machine, 2, 1024);
        let mut command = Command::new("qemu-system-aarch64");
        apply(&mut command, &arm, machine, &dir, 1024, 2).unwrap();
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("type=1,manufacturer=GIGABYTE"))
        );
        for file in ["bios", "chassis", "processor-0", "memory-array", "memory-0"] {
            assert!(dir.join(format!("smbios-{file}.bin")).exists(), "{file}");
        }
        // The processor table carries the MIDR as its ID and ARMv8.
        let tables: Vec<Vec<u8>> = (0..4)
            .filter_map(|index| {
                std::fs::read(dir.join(format!("smbios-processor-{index}.bin"))).ok()
            })
            .collect();
        let type4 = tables.iter().find(|table| table[0] == 4).unwrap();
        assert_eq!(&type4[8..12], &0x413f_d0c1u32.to_le_bytes());
        assert_eq!(u16::from_le_bytes([type4[0x28], type4[0x29]]), 0x0101);
        assert_eq!(
            machine_options(&arm.identity),
            ",x-oem-id=Ampere,x-oem-table-id=Altra"
        );
        assert_eq!(nic_option(&arm), format!("igb,netdev=net0,mac={}", arm.mac));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_desktop_without_uefi_is_a_board_on_its_device_tree() {
        let mut desktop = profile(StealthPreset::RealisticDesktop);
        desktop.firmware = crate::stealth::Firmware::Bios;
        let board = arm_machine(&desktop).unwrap();
        assert_eq!(board.kind, ArmKind::Board);
        // A UEFI machine that cannot boot falls back to a board.
        let server = profile(StealthPreset::RealisticServer);
        assert_eq!(board_for(&server).unwrap().kind, ArmKind::Board);
        let shown = shown_profile(&server, crate::api::GuestArch::AARCH64, &[], 2, 1024);
        assert!(
            ArmMachine::find(&shown.identity.profile)
                .unwrap()
                .tree
                .is_some()
        );
        let shown = shown_profile(
            &server,
            crate::api::GuestArch::X86_64,
            &["uefi".into()],
            2,
            1024,
        );
        assert_eq!(shown, server);

        let node = |name: &str, compatible: &str| fdt::Node {
            name: name.into(),
            props: vec![("compatible".into(), fdt::strings(&[compatible]))],
            children: Vec::new(),
        };
        let mut tree = fdt::Fdt {
            root: fdt::Node {
                name: String::new(),
                props: vec![("compatible".into(), fdt::strings(&["linux,dummy-virt"]))],
                children: vec![
                    fdt::Node {
                        name: "chosen".into(),
                        props: vec![("stdout-path".into(), fdt::strings(&["/pl011@9000000"]))],
                        children: Vec::new(),
                    },
                    node("pl011@9000000", "arm,pl011"),
                    node("fw-cfg@9020000", "qemu,fw-cfg-mmio"),
                    node("virtio_mmio@a000000", "virtio,mmio"),
                    node("platform-bus@c000000", "qemu,platform"),
                    node("pcie@10000000", "pci-host-ecam-generic"),
                    fdt::Node {
                        name: "cpus".into(),
                        props: Vec::new(),
                        children: vec![
                            node("cpu@0", "arm,cortex-a72"),
                            node("cpu@1", "arm,cortex-a72"),
                        ],
                    },
                ],
            },
            reserved: Vec::new(),
            boot_cpuid: 0,
        };
        let pi4 = ArmMachine::find("arm-rpi-4b").unwrap();
        disguise_tree(&mut tree, pi4.tree.as_ref().unwrap(), "4c4c4544-0042-3510");
        let bytes = tree.to_bytes();
        for word in [
            &b"dummy-virt"[..],
            b"qemu,",
            b"virtio,mmio",
            b"fw-cfg",
            b"pl011@",
        ] {
            assert!(!bytes.windows(word.len()).any(|window| window == word));
        }
        let back = fdt::Fdt::parse(&bytes).unwrap();
        assert_eq!(
            back.root.prop("model").unwrap(),
            b"Raspberry Pi 4 Model B Rev 1.4\0"
        );
        assert_eq!(
            back.root.prop("serial-number").unwrap(),
            b"100000004c4c4544\0"
        );
        let names: Vec<&str> = back.root.children.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["chosen", "serial@9000000", "pcie@10000000", "cpus"]);
        // One shared L2 (BCM2711's), each core's L1 and its next level.
        let cpus = &back.root.children[3];
        let l2 = cpus
            .children
            .iter()
            .find(|n| n.name == "l2-cache0")
            .unwrap();
        assert_eq!(l2.prop("cache-size").unwrap(), &0x10_0000u32.to_be_bytes());
        assert_eq!(l2.prop("cache-sets").unwrap(), &1024u32.to_be_bytes());
        let cpu = &cpus.children[0];
        assert_eq!(cpu.prop("i-cache-size").unwrap(), &0xc000u32.to_be_bytes());
        assert_eq!(cpu.prop("next-level-cache"), l2.prop("phandle"));
        // Pi 5: an L2 per core and a shared L3.
        let mut tree5 = fdt::Fdt::parse(&bytes).unwrap();
        let pi5 = ArmMachine::find("arm-rpi-5").unwrap();
        disguise_tree(&mut tree5, pi5.tree.as_ref().unwrap(), "4c4c4544-0042-3510");
        let cpus = tree5.root.child_mut("cpus").unwrap();
        assert!(cpus.children.iter().any(|n| n.name == "l3-cache"));
        let cpu0 = cpus.children.iter().find(|n| n.name == "cpu@0").unwrap();
        assert_eq!(
            cpu0.children[0].prop("cache-size").unwrap(),
            &0x8_0000u32.to_be_bytes()
        );
        assert_eq!(
            back.root.children[0].prop("stdout-path").unwrap(),
            b"/serial@9000000\0"
        );
    }

    #[test]
    fn the_giveaways_follow_the_machine() {
        let aws = ArmMachine::find("arm-aws-graviton2");
        assert!(
            giveaways(aws, true, false)
                .iter()
                .any(|item| item.contains("ENA"))
        );
        assert!(
            giveaways(None, false, false)
                .iter()
                .any(|item| item.contains("dummy-virt"))
        );
        assert!(
            giveaways(None, true, true)
                .iter()
                .any(|item| item.contains("KPTI"))
        );
    }

    #[test]
    fn the_igb_sits_where_its_virtual_functions_fit() {
        // QEMU 11.0.3 refuses igb at 00:19.0 ("VF addr overflows"): its eight
        // virtual functions start at its devfn plus 0x80, two apart. 0e.0 is
        // the highest slot that fits (0x0e starts, 0x0f fails on virt).
        assert!(igb_fits(NicSlot::Virt));
        assert!(igb_fits(NicSlot::Pc));
        for slot in [NicSlot::Ich, NicSlot::Pch, NicSlot::Eno1] {
            assert!(!igb_fits(slot), "{slot:?}");
        }
        assert_eq!(
            NicSlot::Virt.devfn() + IGB_VF_OFFSET + IGB_VF_STRIDE * 7,
            0xfe
        );
        assert_eq!(
            (NicSlot::Virt.address(), NicSlot::Virt.interface()),
            ("addr=0xe", "enp0s14")
        );
        assert_eq!(NicSlot::from_interface("enp0s14"), Some(NicSlot::Virt));
        for preset in [
            StealthPreset::RealisticServer,
            StealthPreset::RealisticDesktop,
            StealthPreset::RealisticLaptop,
            StealthPreset::CloudVps,
        ] {
            let base = profile(preset);
            let machine = arm_machine(&base).unwrap();
            let arm = arm_profile(&base, machine, 2, 2048);
            assert_eq!(
                nic_device(&arm, true, Some(NicSlot::Virt)),
                (format!("igb,netdev=net0,mac={},addr=0xe", arm.mac), None),
                "{preset:?}"
            );
            assert_eq!(nic_device(&arm, true, None), (nic_option(&arm), None));
            // A disk provisioned for 00:19.0 before: the profile's model
            // there (no virtual functions), and the start log says why.
            let (nic, note) = nic_device(&arm, true, Some(NicSlot::Ich));
            assert_eq!(nic, super::super::nic_option_for(&arm, Some(NicSlot::Ich)));
            assert!(
                !nic.starts_with("igb") && nic.ends_with(",addr=0x19"),
                "{nic}"
            );
            let note = note.unwrap();
            assert!(
                note.contains("enp0s25") && note.contains("enp0s14"),
                "{note}"
            );
        }
        // Transparent (no arm64 machine): the profile's own model, as before.
        let plain = StealthProfile::transparent();
        for slot in [None, Some(NicSlot::Virt), Some(NicSlot::Ich)] {
            assert_eq!(
                nic_device(&plain, false, slot),
                (super::super::nic_option_for(&plain, slot), None)
            );
        }
    }
}
