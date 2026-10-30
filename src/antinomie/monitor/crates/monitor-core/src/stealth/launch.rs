// SPDX-License-Identifier: GPL-3.0-only
//! The device profile as QEMU launch options. Each one adds only what
//! differs from QEMU's defaults, so a Transparent profile launches as before.
use super::{
    DiskBus, DiskMedia, Firmware, NicModel, NicSlot, Pointer, RtcClock, SmbiosEntry, StealthPreset,
    StealthProfile, firmware, host_cpu_vendor, host_cpuinfo, memory, processor, smbios,
};
use std::{path::Path, process::Command};

/// QEMU option values double their commas.
pub(crate) fn escape(text: &str) -> String {
    text.replace(',', ",,")
}

/// A `vendor:device` pair of 16-bit hex IDs.
pub(super) fn pci_ids(text: &str) -> Option<(u16, u16)> {
    let (vendor, device) = text.split_once(':')?;
    let hex = |part: &str| {
        (part.len() == 4)
            .then(|| u16::from_str_radix(part, 16).ok())
            .flatten()
    };
    Some((hex(vendor)?, hex(device)?))
}

/// Extra `-machine` properties.
pub(crate) fn machine_options(profile: &StealthProfile) -> String {
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
    if profile.firmware == Firmware::UefiSecureBoot {
        // Secure Boot firmware keeps its variables in SMM-only flash.
        options.push_str(",smm=on");
    } else if !profile.smm {
        options.push_str(",smm=off");
    }
    if profile.identity_enabled {
        options.push_str(match profile.smbios_entry {
            SmbiosEntry::Bits64 => ",smbios-entry-point-type=64",
            SmbiosEntry::Bits32 => ",smbios-entry-point-type=32",
        });
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

/// Two threads per core in effect: one socket and an even CPU count.
fn smt(profile: &StealthProfile, cpus: u16) -> bool {
    profile.smt && profile.realistic_topology && cpus >= 2 && cpus.is_multiple_of(2)
}

/// The `-cpu` value: `base` (from the VM's CPU model setting) with the
/// profile's CPU entries. Passthrough needs KVM.
pub(crate) fn cpu_option(
    profile: &StealthProfile,
    base: Option<&str>,
    kvm: bool,
    cpus: u16,
) -> Option<String> {
    let named = !profile.cpu_passthrough && !profile.cpu_model.is_empty();
    let mut model = if profile.cpu_passthrough && kvm {
        "host".to_owned()
    } else if profile.cpu_passthrough {
        // Without KVM the host CPU cannot be passed through; show its name.
        let brand = host_cpuinfo("model name")
            .unwrap_or_else(|| "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz".into());
        format!("max,model-id={}", escape(&brand))
    } else if named {
        profile.cpu_model.clone()
    } else {
        base?.to_owned()
    };
    if model.is_empty() {
        return None;
    }
    if !profile.cpu_passthrough && !profile.cpu_brand.is_empty() {
        model.push_str(&format!(",model-id={}", escape(&profile.cpu_brand)));
    }
    if profile.host_cache_info && model == "host" {
        model.push_str(",host-cache-info=on");
    }
    if named && profile.model_cache_info {
        // The named model's caches (leaf 4, 0x8000001d) and an L3.
        model.push_str(",legacy-cache=off,l3-cache=on");
    }
    if smt(profile, cpus) && matches!(host_cpu_vendor().as_str(), "AuthenticAMD" | "HygonGenuine") {
        // AMD CPUs show their threads through the TOPOEXT leaves.
        model.push_str(",+topoext");
    }
    if profile.hide_hypervisor {
        model.push_str(",-hypervisor");
    }
    if profile.hide_kvm && kvm {
        model.push_str(",kvm=off");
    } else if !profile.kvm_clock && kvm {
        model.push_str(",-kvmclock");
    }
    if profile.pmu && kvm {
        model.push_str(",pmu=on");
    }
    Some(model)
}

/// The `-smp` value.
pub(crate) fn smp_option(profile: &StealthProfile, cpus: u16) -> String {
    if smt(profile, cpus) {
        format!("{cpus},sockets=1,cores={},threads=2", cpus / 2)
    } else if profile.realistic_topology {
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
    if profile.identity_enabled
        && profile.nic == NicModel::E1000e
        && let Some((vendor, id)) = pci_ids(&profile.identity.nic_subsystem)
    {
        device.push_str(&format!(",subsys_ven={vendor},subsys={id}"));
    }
    device
}

/// [`nic_option`] at `slot`, for a base that names its NIC by PCI slot
/// (stealth support `onboardnic`); elsewhere QEMU picks the first free slot.
pub(crate) fn nic_option_for(profile: &StealthProfile, slot: Option<NicSlot>) -> String {
    let mut device = nic_option(profile);
    if let Some(slot) = slot {
        device.push(',');
        device.push_str(slot.address());
    }
    device
}

/// The `-netdev user` value: `base` (`user,id=net0` with its restrictions)
/// with the profile's addresses.
pub(crate) fn netdev_option(base: &str, profile: &StealthProfile) -> String {
    format!("{base}{}", profile.nat.options())
}

/// The root disk: `image` (an escaped path) on the profile's bus, always
/// as block device `osdisk` so snapshots find it by that name.
pub(crate) fn disk_args(profile: &StealthProfile, image: &str) -> Vec<String> {
    let drive = |interface: &str| {
        format!("file={image},format=qcow2,if={interface},id=osdisk,node-name=antinomie-disk")
    };
    let id = &profile.identity;
    let named = |name: &str, value: &str| {
        if profile.identity_enabled && !value.is_empty() {
            format!(",{name}={}", escape(value))
        } else {
            String::new()
        }
    };
    match profile.disk_bus {
        DiskBus::Virtio => vec!["-drive".into(), drive("virtio")],
        DiskBus::Sata => {
            let mut device = format!(
                "ide-hd,drive=osdisk,bus=ide.0{}{}{}",
                named("model", &id.disk_model),
                named("serial", &id.disk_serial),
                named("ver", &id.disk_firmware)
            );
            if profile.identity_enabled && !id.disk_wwn.is_empty() {
                device.push_str(&format!(",wwn=0x{}", id.disk_wwn));
            }
            // The identity's disk's own rate when it matches the media (a
            // 5,400 rpm laptop disk), else the media's.
            let rotation = match (profile.disk_media, id.disk_rotation) {
                (DiskMedia::Hdd, rpm) if profile.identity_enabled && rpm > 1 => rpm,
                (DiskMedia::Hdd, _) => 7200,
                (DiskMedia::Ssd, _) => 1,
            };
            device.push_str(&format!(",rotation_rate={rotation}"));
            vec!["-drive".into(), drive("none"), "-device".into(), device]
        }
        DiskBus::Nvme => {
            // The controller's model, firmware revision and subsystem name
            // (nqn.2019-08.org.qemu:<serial>) are QEMU's; the serial and the
            // PCI vendor can be set.
            let serial = if profile.identity_enabled && !id.disk_serial.is_empty() {
                escape(&id.disk_serial)
            } else {
                "0000000000000000".into()
            };
            vec![
                "-drive".into(),
                drive("none"),
                "-device".into(),
                format!("nvme,drive=osdisk,serial={serial},use-intel-id=on"),
            ]
        }
    }
}

/// The pointer beside a display.
pub(crate) fn pointer_args(profile: &StealthProfile) -> &'static [&'static str] {
    match profile.pointer {
        Pointer::VirtioTablet => &["-device", "virtio-tablet-pci"],
        Pointer::UsbTablet => &["-device", "usb-tablet"],
        Pointer::Ps2 => &[],
    }
}

/// OVMF in two flash devices, with the VM's own variable store kept in
/// `vm_dir`; nothing for BIOS.
pub(crate) fn firmware_args(
    command: &mut Command,
    profile: &StealthProfile,
    qemu: &Path,
    vm_dir: &Path,
) -> Result<(), String> {
    if !profile.firmware.is_uefi() {
        return Ok(());
    }
    let secure_boot = profile.firmware == Firmware::UefiSecureBoot;
    let ovmf = firmware::find_ovmf(qemu, secure_boot)?;
    let vars = firmware::vm_vars(&ovmf, vm_dir, secure_boot)?;
    let path = |path: &Path| {
        path.to_str()
            .map(escape)
            .ok_or_else(|| format!("{} is not UTF-8", path.display()))
    };
    command.arg("-drive").arg(format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        path(&ovmf.code)?
    ));
    command
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,unit=1,file={}", path(&vars)?));
    if secure_boot {
        command.args(["-global", "driver=cfi.pflash01,property=secure,value=on"]);
    }
    Ok(())
}

/// The SMBIOS processor family of a CPU brand string (SMBIOS 3.x "processor
/// family 2"), for the families real machines in the catalog report; None
/// for any other.
pub(super) fn processor_family(brand: &str) -> Option<u16> {
    let families = [
        ("Core(TM) i3", 0xce),
        ("Core(TM) i5", 0xcd),
        ("Core(TM) i7", 0xc6),
        ("Core(TM) i9", 0xcf),
        ("Xeon", 0xb3),
        ("Pentium", 0x0b),
        ("Celeron", 0x0f),
        ("Ryzen", 0x6b),
        ("EPYC", 0x6b),
    ];
    families
        .iter()
        .find(|(name, _)| brand.contains(name))
        .map(|(_, family)| *family)
}

/// The processor's maximum and current speed in MHz, as firmware reports
/// them: the highest clock (cpufreq's `cpuinfo_max_freq`, in kHz) and the
/// base clock (cpufreq's `base_frequency`, the brand string's "@ 2.90GHz",
/// else the clock /proc/cpuinfo shows), each to 50 MHz.
pub(super) fn cpu_speeds(
    max_khz: Option<u64>,
    base_khz: Option<u64>,
    brand: &str,
    cpuinfo_mhz: Option<f64>,
) -> Option<(u16, u16)> {
    let branded = brand
        .rsplit_once('@')
        .and_then(|(_, clock)| clock.trim().strip_suffix("GHz"))
        .and_then(|ghz| ghz.trim().parse::<f64>().ok())
        .map(|ghz| ghz * 1000.0);
    let base = base_khz
        .map(|khz| khz as f64 / 1000.0)
        .or(branded)
        .or(cpuinfo_mhz)?;
    let max = max_khz.map_or(base, |khz| khz as f64 / 1000.0).max(base);
    let mhz = |value: f64| ((value / 50.0).round() * 50.0).clamp(50.0, 65000.0) as u16;
    Some((mhz(max), mhz(base)))
}

/// [`cpu_speeds`] of the host's first CPU.
pub(super) fn host_cpu_speeds() -> Option<(u16, u16)> {
    let khz = |name: &str| {
        std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu0/cpufreq/{name}"))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
    };
    cpu_speeds(
        khz("cpuinfo_max_freq"),
        khz("base_frequency"),
        &host_cpuinfo("model name").unwrap_or_default(),
        host_cpuinfo("cpu MHz").and_then(|text| text.parse().ok()),
    )
}

/// QEMU's own type 4 option, for a VM with a socket per vCPU.
fn processor_option(id: &super::MachineIdentity) -> String {
    let (cpu_vendor, cpu_name) = (
        host_cpu_vendor(),
        host_cpuinfo("model name").unwrap_or_default(),
    );
    let cpu_maker = match cpu_vendor.as_str() {
        "GenuineIntel" => "Intel(R) Corporation",
        "AuthenticAMD" => "Advanced Micro Devices, Inc.",
        _ => "",
    };
    let socket = match (id.cpu_socket.as_str(), cpu_vendor.as_str()) {
        ("", "AuthenticAMD") => "AM4",
        ("", _) => "U3E1",
        (socket, _) => socket,
    };
    let part = if id.cpu_part.is_empty() {
        String::new()
    } else {
        format!(",part={}", escape(&id.cpu_part))
    };
    let mut processor = format!(
        "type=4,sock_pfx={},manufacturer={},version={}{part}",
        escape(socket),
        escape(cpu_maker),
        escape(&cpu_name)
    );
    if let Some((max, current)) = host_cpu_speeds() {
        processor.push_str(&format!(",max-speed={max},current-speed={current}"));
    }
    if let Some(family) = processor_family(&cpu_name) {
        processor.push_str(&format!(",processor-family={family}"));
    }
    processor
}

/// SMBIOS, device identity, CD-ROM and clock options; the BIOS, chassis and
/// memory device tables are written into `runtime_dir`. Every SMBIOS field
/// QEMU fills with its own value when it is left out (its name, "Standard
/// PC", the machine type as a version, "CPU 0", 2000 MHz, "DIMM 0") is given,
/// an empty one as string 0, which reads "Not Specified".
pub(crate) fn apply(
    command: &mut Command,
    profile: &StealthProfile,
    runtime_dir: &Path,
    ram_mib: u32,
    cpus: u16,
) -> Result<(), String> {
    profile.validate()?;
    let mut rtc = Vec::new();
    if profile.rtc_localtime {
        rtc.push("base=localtime");
    }
    if profile.rtc_clock == RtcClock::Vm {
        rtc.push("clock=vm");
    }
    if profile.rtc_driftfix {
        rtc.push("driftfix=slew");
    }
    if !rtc.is_empty() {
        command.arg("-rtc").arg(rtc.join(","));
    }
    if profile.cdrom {
        // An empty drive on the second port of q35's AHCI controller.
        command.args(["-device", "ide-cd,bus=ide.1"]);
    }
    if !profile.identity_enabled {
        return Ok(());
    }
    let id = &profile.identity.with_firmware_fields();
    let field = |name: &str, value: &str| {
        if value.is_empty() {
            String::new()
        } else {
            format!(",{name}={}", escape(value))
        }
    };
    // A field QEMU would fill: given even when empty.
    let given = |name: &str, value: &str| format!(",{name}={}", escape(value));
    let write_table = |name: &str, table: Vec<u8>| -> Result<String, String> {
        let path = runtime_dir.join(name);
        std::fs::write(&path, table).map_err(|error| format!("SMBIOS {name}: {error}"))?;
        Ok(format!("file={}", escape(&path.to_string_lossy())))
    };
    // QEMU's type 0 sets the "virtual machine" BIOS characteristic, which
    // systemd-detect-virt reads, so the BIOS table is written whole too.
    let bios = write_table(
        "smbios-bios.bin",
        smbios::bios_table(id, profile.firmware.is_uefi()),
    )?;
    command.arg("-smbios").arg(bios);
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
        "type=2{}{}{}{}{}",
        given("manufacturer", &id.board_manufacturer),
        given("product", &id.board_product),
        given("version", &id.board_version),
        field("serial", &id.board_serial),
        field("location", &id.board_location)
    ));
    // One physical processor, whole, when the VM has one socket; QEMU's own
    // option (a socket per vCPU, each numbered after the designation) when
    // the topology is not the realistic one.
    let per_core = if smt(profile, cpus) { 2 } else { 1 };
    let processor = profile
        .realistic_topology
        .then(|| processor::Processor::of_host(id, cpus.div_ceil(per_core).max(1), cpus.max(1)))
        .flatten();
    if let Some(processor) = processor {
        for (index, table) in processor.tables().into_iter().enumerate() {
            let file = write_table(&format!("smbios-processor-{index}.bin"), table)?;
            command.arg("-smbios").arg(file);
        }
    } else {
        command.arg("-smbios").arg(processor_option(id));
    }
    if !id.oem_strings.is_empty() {
        let values: String = id
            .oem_strings
            .iter()
            .map(|text| field("value", text))
            .collect();
        command.arg("-smbios").arg(format!("type=11{values}"));
    }
    let ecc = id.memory_detail & 0x2000 != 0
        || super::MACHINES.iter().any(|machine| {
            machine.id == id.profile && machine.kind == StealthPreset::RealisticServer
        });
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
    // QEMU's type 3 options cannot set the chassis type, so the table is
    // written whole and loaded in place of the generated one.
    let chassis = write_table("smbios-chassis.bin", smbios::chassis_table(id))?;
    command.arg("-smbios").arg(chassis);
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
