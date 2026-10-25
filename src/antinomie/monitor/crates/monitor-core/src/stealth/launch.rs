// SPDX-License-Identifier: GPL-3.0-only
//! The stealth profile as QEMU launch options. Each one adds only what
//! differs from QEMU's defaults, so a Transparent profile launches as before.
use super::{
    DiskBus, DiskMedia, Firmware, NicModel, NicSlot, Pointer, RtcClock, SmbiosEntry,
    StealthProfile, firmware, host_cpu_vendor, host_cpuinfo, smbios,
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
            device.push_str(match profile.disk_media {
                DiskMedia::Ssd => ",rotation_rate=1",
                DiskMedia::Hdd => ",rotation_rate=7200",
            });
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

/// SMBIOS, device identity, CD-ROM and clock options; the BIOS and chassis
/// tables are written into `runtime_dir`.
pub(crate) fn apply(
    command: &mut Command,
    profile: &StealthProfile,
    runtime_dir: &Path,
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
    let id = &profile.identity;
    let field = |name: &str, value: &str| {
        if value.is_empty() {
            String::new()
        } else {
            format!(",{name}={}", escape(value))
        }
    };
    // QEMU's type 0 sets the "virtual machine" BIOS characteristic, which
    // systemd-detect-virt reads, so the BIOS table is written whole too.
    let bios = runtime_dir.join("smbios-bios.bin");
    std::fs::write(&bios, smbios::bios_table(id, profile.firmware.is_uefi()))
        .map_err(|error| format!("SMBIOS BIOS table: {error}"))?;
    command
        .arg("-smbios")
        .arg(format!("file={}", escape(&bios.to_string_lossy())));
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
    if !id.oem_strings.is_empty() {
        let values: String = id
            .oem_strings
            .iter()
            .map(|text| field("value", text))
            .collect();
        command.arg("-smbios").arg(format!("type=11{values}"));
    }
    command.arg("-smbios").arg(format!(
        "type=17{}{}{},speed=3200",
        field("manufacturer", &id.memory_manufacturer),
        field("part", &id.memory_part),
        field("serial", &id.memory_serial)
    ));
    // QEMU's type 3 options cannot set the chassis type, so the table is
    // written whole and loaded in place of the generated one.
    let chassis = runtime_dir.join("smbios-chassis.bin");
    std::fs::write(&chassis, smbios::chassis_table(id))
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
