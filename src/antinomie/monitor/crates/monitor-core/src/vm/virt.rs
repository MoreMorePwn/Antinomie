// SPDX-License-Identifier: GPL-3.0-only
//! The QEMU options of an arm64 VM: `virt` under TCG (MA-09, MA-16), with the
//! kernel booted directly on QEMU's device tree, or through AAVMF (UEFI with
//! ACPI) when the device profile asks for UEFI and the base boots it.
//!
//! The device profile's x86 identity (SMBIOS, CPUID, q35 devices) does not
//! apply here; what does is its network (NAT addresses, MAC, card model) and
//! its root disk bus where `virt` has it. arm64 device profiles come with
//! MA-17; until then the CPU is a named Cortex/Neoverse model, never `max`.
use crate::stealth::{DiskBus, StealthProfile};
use std::{path::Path, process::Command};

/// The CPU of a VM booted on the device tree (a Raspberry Pi 4's core) and of
/// one booted through UEFI (an Ampere Altra's).
pub(crate) const DT_CPU: &str = "cortex-a72";
pub(crate) const UEFI_CPU: &str = "neoverse-n1";

/// What an arm64 VM's display shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtDisplay {
    /// No screen at all (`-display none`, no GPU).
    pub headless: bool,
    /// The QEMU window (GTK); otherwise the app's screen, whose VNC display
    /// the launch adds (`-display none`, the same devices).
    pub window: bool,
    /// A fixed mode for virtio-gpu, else the guest's default.
    pub resolution: Option<(u16, u16)>,
    pub fullscreen: bool,
    pub fit_to_window: bool,
}

/// The machine, CPU and accelerator options. `uefi`: the firmware's code and
/// the VM's variable store, in the two flash devices.
pub(crate) fn machine_args(
    command: &mut Command,
    ram_mib: u32,
    ram_path: &str,
    cpus: u16,
    uefi: Option<(&Path, &Path)>,
) -> Result<(), String> {
    command
        .arg("-machine")
        .arg("virt,gic-version=3,memory-backend=shared")
        .arg("-object")
        .arg(format!(
            "memory-backend-file,id=shared,size={ram_mib}M,mem-path={ram_path},share=on"
        ))
        .arg("-m")
        .arg(ram_mib.to_string())
        .arg("-smp")
        .arg(cpus.to_string())
        // No KVM for a foreign architecture: TCG, one host thread per vCPU.
        .args(["-accel", "tcg"])
        .arg("-cpu")
        .arg(if uefi.is_some() { UEFI_CPU } else { DT_CPU });
    if let Some((code, vars)) = uefi {
        let path = |path: &Path| {
            path.to_str()
                .map(crate::stealth::escape)
                .ok_or_else(|| format!("{} is not UTF-8", path.display()))
        };
        command.arg("-drive").arg(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            path(code)?
        ));
        command
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,unit=1,file={}", path(vars)?));
    }
    Ok(())
}

/// The root disk on the profile's bus where `virt` has it: virtio and NVMe
/// are PCI devices there; it has no SATA controller of its own, so a SATA
/// profile gets an AHCI controller (ICH9's, as on q35) for its disk.
pub(crate) fn disk_args(profile: &StealthProfile, image: &str) -> Vec<String> {
    let mut args = Vec::new();
    if profile.disk_bus == DiskBus::Sata {
        args.extend(["-device".into(), "ich9-ahci,id=ide".into()]);
    }
    args.extend(crate::stealth::disk_args(profile, image));
    args
}

/// The kernel command line's additions: the bootstrap page, and with
/// `fast_emulation` KPTI off (`antinomie_kpti=off`, which the guest takes
/// out of the command line it shows).
pub(crate) fn append(base: &str, bootstrap: u64, fast_emulation: bool) -> String {
    let mut append = format!("{base} antinomie_boot_gpa=0x{bootstrap:x}");
    if fast_emulation {
        append.push_str(" antinomie_kpti=off");
    }
    append
}

/// The display, keyboard and pointer: virtio-gpu and USB (xHCI) devices, as
/// arm64 machines have no VGA or PS/2, shown in the QEMU window or (display
/// `none`) on the in-app screen's VNC display. `append` gets the fixed mode.
pub(crate) fn display_args(command: &mut Command, display: VirtDisplay, append: &mut String) {
    if display.headless {
        command.args(["-display", "none"]);
        return;
    }
    let gpu = match display.resolution {
        Some((width, height)) => {
            append.push_str(&format!(" video=Virtual-1:{width}x{height}"));
            format!("virtio-gpu-pci,edid=on,xres={width},yres={height}")
        }
        None => "virtio-gpu-pci".into(),
    };
    command
        .args(["-device", &gpu])
        .args(["-device", "qemu-xhci,id=xhci"])
        .args(["-device", "usb-kbd,bus=xhci.0"])
        .args(["-device", "usb-tablet,bus=xhci.0"]);
    if !display.window {
        command.args(["-display", "none"]);
        return;
    }
    let mut value = "gtk".to_owned();
    if display.fullscreen {
        value.push_str(",full-screen=on");
    }
    value.push_str(if display.fit_to_window {
        ",zoom-to-fit=on"
    } else {
        ",zoom-to-fit=off"
    });
    command.arg("-display").arg(value);
}

/// What still tells an arm64 VM apart from a real arm64 machine, most telling
/// first (the device profile's own list covers its network and disk).
pub(crate) fn giveaways(uefi: bool, fast_emulation: bool) -> Vec<&'static str> {
    let mut found = vec![
        "instruction timing of an emulated CPU (TCG, no hardware virtualisation)",
        if uefi {
            "QEMU's ACPI tables and AAVMF's vendor (EDK II) in the EFI tables, to root"
        } else {
            "QEMU's device tree: linux,dummy-virt, fw-cfg and virtio-mmio nodes"
        },
        "the virt machine's PCIe host bridge (Red Hat vendor ID)",
    ];
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

    fn args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn a_direct_boot_uses_the_device_tree_cpu_and_tcg() {
        let mut command = Command::new("qemu-system-aarch64");
        machine_args(&mut command, 1024, "/run/ram", 2, None).unwrap();
        assert_eq!(
            args(&command),
            [
                "-machine",
                "virt,gic-version=3,memory-backend=shared",
                "-object",
                "memory-backend-file,id=shared,size=1024M,mem-path=/run/ram,share=on",
                "-m",
                "1024",
                "-smp",
                "2",
                "-accel",
                "tcg",
                "-cpu",
                "cortex-a72"
            ]
        );
        let mut command = Command::new("qemu-system-aarch64");
        machine_args(
            &mut command,
            1024,
            "/run/ram",
            2,
            Some((Path::new("/fw/code,a.fd"), Path::new("/vm/vars.fd"))),
        )
        .unwrap();
        let args = args(&command);
        assert!(args.contains(&"neoverse-n1".to_owned()));
        assert!(
            args.contains(&"if=pflash,format=raw,unit=0,readonly=on,file=/fw/code,,a.fd".into())
        );
        assert!(args.contains(&"if=pflash,format=raw,unit=1,file=/vm/vars.fd".into()));
    }

    #[test]
    fn fast_emulation_turns_kpti_off_through_a_taken_option() {
        assert_eq!(
            append("console=ttyAMA0", 0x6000_0000, false),
            "console=ttyAMA0 antinomie_boot_gpa=0x60000000"
        );
        assert_eq!(
            append("console=ttyAMA0", 0x6000_0000, true),
            "console=ttyAMA0 antinomie_boot_gpa=0x60000000 antinomie_kpti=off"
        );
        assert!(
            giveaways(false, true)
                .iter()
                .any(|item| item.contains("KPTI"))
        );
        assert!(
            !giveaways(false, false)
                .iter()
                .any(|item| item.contains("KPTI"))
        );
    }

    #[test]
    fn a_window_gets_virtio_gpu_and_usb_input() {
        let mut command = Command::new("qemu-system-aarch64");
        let mut append = String::new();
        display_args(
            &mut command,
            VirtDisplay {
                headless: false,
                window: true,
                resolution: Some((1280, 800)),
                fullscreen: false,
                fit_to_window: true,
            },
            &mut append,
        );
        let window = args(&command);
        assert!(window.contains(&"virtio-gpu-pci,edid=on,xres=1280,yres=800".to_owned()));
        assert!(window.contains(&"usb-kbd,bus=xhci.0".to_owned()));
        assert_eq!(window.last().unwrap(), "gtk,zoom-to-fit=on");
        assert_eq!(append, " video=Virtual-1:1280x800");
        // The in-app screen: the same devices, no window (VNC is the launch's).
        let mut command = Command::new("qemu-system-aarch64");
        let mut in_app = String::new();
        display_args(
            &mut command,
            VirtDisplay {
                headless: false,
                window: false,
                resolution: Some((1280, 800)),
                fullscreen: false,
                fit_to_window: true,
            },
            &mut in_app,
        );
        let screen = args(&command);
        assert_eq!(screen[..screen.len() - 2], window[..window.len() - 2]);
        assert_eq!(screen[screen.len() - 2..], ["-display", "none"]);
        assert_eq!(in_app, append);
        let mut command = Command::new("qemu-system-aarch64");
        display_args(
            &mut command,
            VirtDisplay {
                headless: true,
                window: false,
                resolution: None,
                fullscreen: false,
                fit_to_window: false,
            },
            &mut append,
        );
        assert_eq!(super::tests::args(&command), ["-display", "none"]);
    }

    #[test]
    fn a_sata_profile_gets_a_controller_on_virt() {
        let mut profile = StealthProfile {
            disk_bus: DiskBus::Sata,
            ..StealthProfile::default()
        };
        let args = disk_args(&profile, "/vm/disk.qcow2");
        assert_eq!(&args[..2], ["-device", "ich9-ahci,id=ide"]);
        profile.disk_bus = DiskBus::Virtio;
        assert_eq!(disk_args(&profile, "/vm/disk.qcow2")[0], "-drive");
    }
}
