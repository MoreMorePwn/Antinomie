// SPDX-License-Identifier: GPL-3.0-only
//! What still tells a VM apart under its device profile: the Device profile
//! window's and the Overview's "Still visible" list. Every entry follows the
//! profile as the VM starts it and the VM's own settings (architecture,
//! network, display, base), so an entry the configuration hides is not
//! listed and one it causes is.
use super::{
    BootAge, ClockModel, DiskBus, Firmware, MACHINES, MachineType, NicModel, Pointer,
    StealthProfile, arm64, launch,
};
use crate::api::{BaseSummary, GuestArch, VmConfig, VmNetwork};

/// The device that shows the VM's screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Display {
    /// QEMU's standard VGA (Bochs): an x86 VM without a fixed resolution.
    #[default]
    StdVga,
    /// virtio-vga: a graphical guest base without a fixed resolution.
    VirtioVga,
    /// virtio-gpu: a fixed resolution, and every arm64 VM.
    VirtioGpu,
}

/// The VM's settings beside its profile that the list reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmView {
    pub arch: GuestArch,
    /// An arm64 VM booted without KPTI (Faster emulation).
    pub fast_emulation: bool,
    /// The base runs Debian's own modules (systemd).
    pub debian: bool,
    /// The base's kernel has the guest facade (`facade`).
    pub facade: bool,
    /// An arm64 VM can boot UEFI: its base supports it and AAVMF is here.
    pub uefi: bool,
    pub display: Display,
    pub network: VmNetwork,
}

impl Default for VmView {
    /// An x86-64 VM on NAT with the standard VGA, on a base with every
    /// feature and without Debian's modules.
    fn default() -> Self {
        Self {
            arch: GuestArch::default(),
            fast_emulation: false,
            debian: false,
            facade: true,
            uefi: true,
            display: Display::StdVga,
            network: VmNetwork::Nat,
        }
    }
}

impl VmView {
    /// `vm` on `base` (None: not installed, every feature assumed), with
    /// `uefi_firmware` telling whether this host has the arm64 UEFI
    /// firmware (AAVMF).
    pub fn of(vm: &VmConfig, base: Option<&BaseSummary>, uefi_firmware: bool) -> Self {
        let support = base.map_or_else(super::BaseSupport::all, |base| {
            super::BaseSupport::from_list(&base.stealth_support)
        });
        let arch = base.map_or_else(GuestArch::default, |base| base.arch);
        let display = if arch == GuestArch::AARCH64 || vm.launch.resolution.dimensions().is_some() {
            Display::VirtioGpu
        } else if base
            .and_then(|base| base.guest.as_ref())
            .is_some_and(|guest| guest.graphical)
        {
            Display::VirtioVga
        } else {
            Display::StdVga
        };
        Self {
            arch,
            fast_emulation: vm.launch.fast_emulation,
            debian: base.is_some_and(|base| base.guest.is_some()),
            facade: support.facade,
            uefi: support.uefi && uefi_firmware,
            display,
            network: vm.network(),
        }
    }

    fn has_card(&self) -> bool {
        self.network != VmNetwork::Disconnected
    }
}

impl StealthProfile {
    /// What still tells this VM apart, most telling first. `self` is the
    /// profile as the VM starts it ([`fitted`](Self::fitted)).
    pub fn still_visible(&self, view: &VmView) -> Vec<&'static str> {
        if view.arch == GuestArch::AARCH64 {
            return self.arm64_giveaways(view);
        }
        if self.arch_fallback(view.arch).is_some() {
            // An IoT profile on x86-64 starts as Normal QEMU.
            return Self::transparent().still_visible(view);
        }
        if self.cloud_provider().is_some() {
            return self.cloud_giveaways(view);
        }
        self.x86_giveaways(view)
    }

    /// [`still_visible`](Self::still_visible) for a VM of `arch` with the
    /// default view's other settings.
    pub fn giveaways_for(
        &self,
        arch: GuestArch,
        fast_emulation: bool,
        debian: bool,
    ) -> Vec<&'static str> {
        self.still_visible(&VmView {
            arch,
            fast_emulation,
            debian,
            ..VmView::default()
        })
    }

    /// What still tells an x86-64 VM apart on a base that does not run
    /// Debian's modules ([`VmView::default`]).
    pub fn giveaways(&self) -> Vec<&'static str> {
        self.giveaways_on(false)
    }

    /// [`giveaways`](Self::giveaways) on a base that runs Debian's modules
    /// (`debian`) or not.
    pub fn giveaways_on(&self, debian: bool) -> Vec<&'static str> {
        self.still_visible(&VmView {
            debian,
            ..VmView::default()
        })
    }

    fn arm64_giveaways(&self, view: &VmView) -> Vec<&'static str> {
        let machine = arm64::presented(self, view.uefi);
        let mut found = arm64::giveaways(
            machine,
            machine.is_some() || (self.firmware.is_uefi() && view.uefi),
            view.fast_emulation,
        );
        if machine.is_none() && view.has_card() {
            // QEMU's own identity keeps the profile's card and address.
            if self.mac.is_empty() {
                found.push("QEMU's MAC address 52:54:00:12:34:56");
            }
            if self.nic == NicModel::VirtioNet {
                found.push("virtio network card (Red Hat vendor ID)");
            }
        }
        if machine.is_none() && self.disk_bus == DiskBus::Virtio {
            found.push("virtio disk vda (Red Hat vendor ID)");
        }
        found.push("the emulated display (virtio-gpu)");
        found.push(self.uptime_giveaway(view.debian));
        found
    }

    fn x86_giveaways(&self, view: &VmView) -> Vec<&'static str> {
        let mut found = Vec::new();
        // A desktop or laptop machine on a base with the guest facade
        // (patch 0052): its GPU, NVMe drive, board subsystem, ACPI creator,
        // mouse and EFI vendor are shown for QEMU's.
        let facade = view.facade && !launch::facade_options(self, false).is_empty();
        if !self.hide_hypervisor {
            found.push("CPUID hypervisor flag");
        }
        if !self.hide_kvm {
            found.push(if self.kvm_clock {
                "KVM CPUID signature and kvm-clock"
            } else {
                "KVM CPUID signature"
            });
        }
        if !self.identity_enabled {
            found.push("QEMU in the SMBIOS and ACPI tables, chassis type Other");
        }
        if !self.cpu_passthrough {
            found.push(if self.cpu_brand.is_empty() {
                "QEMU CPU model name"
            } else {
                "the QEMU CPU model's family and model numbers behind its brand"
            });
        } else if !self.cpu_brand.is_empty() {
            found.push("the host CPU's family, model and feature flags behind the brand string");
        }
        if !self.realistic_topology {
            found.push("one socket per CPU, QEMU's default topology");
        }
        if view.has_card() {
            if self.mac.is_empty() {
                found.push("QEMU's MAC address 52:54:00:12:34:56");
            }
            if self.nic == NicModel::VirtioNet {
                found.push("virtio network card (Red Hat vendor ID)");
            } else if self.identity_enabled
                && let Some(machine) = MACHINES
                    .iter()
                    .find(|machine| machine.id == self.identity.profile)
            {
                found.extend(machine.nic_fit().giveaway());
            }
        }
        match self.disk_bus {
            DiskBus::Virtio => found.push("virtio disk vda (Red Hat vendor ID)"),
            DiskBus::Sata if !self.identity_enabled || self.identity.disk_model.is_empty() => {
                found.push("SATA disk model QEMU HARDDISK")
            }
            DiskBus::Sata => {}
            DiskBus::Nvme if facade && self.identity.nvme_drive().is_some() => {}
            DiskBus::Nvme => found.push(
                "NVMe controller model QEMU NVMe Ctrl, QEMU's version as firmware, an org.qemu subsystem name",
            ),
        }
        if self.cdrom {
            found.push("the CD-ROM's SCSI inquiry: QEMU DVD-ROM");
        }
        if self.vmport {
            found.push("VMware backdoor port");
        }
        if !self.usb {
            found.push("no USB controller");
        }
        if !self.hpet {
            found.push("no HPET timer, which every PC has");
        }
        if !self.pmu {
            found.push("no performance counters");
        }
        match self.firmware {
            Firmware::Bios => found.push("BIOS firmware (SeaBIOS): no /sys/firmware/efi"),
            _ if facade => found.push(
                "OVMF's boot entries in efivarfs name QEMU's devices; its vendor (EDK II) in the EFI system table, to root reading memory",
            ),
            _ => found.push("OVMF's vendor (EDK II) in the EFI tables, to root"),
        }
        if self.nat.network.is_empty() && view.has_card() {
            found.push("QEMU's default guest network (10.0.2.x)");
        }
        if self.pointer == Pointer::VirtioTablet || (self.pointer == Pointer::UsbTablet && !facade)
        {
            found.push("the pointer's input name (QEMU) in the VM window");
        } else if self.pointer == Pointer::UsbTablet {
            found.push("the USB tablet's strings to a program that asks the device (usbfs), and its absolute axes");
        }
        found.push("timing of VM exits (CPUID, I/O) and of traced calls");
        if facade {
            found.push("QEMU's PCI IDs to root reading config space through I/O ports");
            found.push(match self.machine {
                MachineType::Q35 => {
                    "the q35 chipset's ICH9 (2009) device IDs behind the board's subsystem"
                }
                MachineType::Pc => {
                    "the i440FX chipset's PIIX3 (1996) device IDs behind the board's subsystem"
                }
            });
            found.push(match view.display {
                Display::StdVga => {
                    "the display's Bochs layout (registers, modes) behind its GPU name"
                }
                Display::VirtioVga => "the display is virtio-vga (Red Hat vendor ID)",
                Display::VirtioGpu => "the display is virtio-gpu (Red Hat vendor ID)",
            });
            if view.debian {
                found.extend([
                    "udev's device database: the devices' true PCI IDs",
                    "Debian's own NVMe, DRM, USB and libata modules: QEMU's NVMe Identify data, display driver names, USB HID strings and default DVD-ROM",
                ]);
            }
        } else {
            found.push(display_text(view.display));
            found.push(match self.machine {
                MachineType::Q35 => {
                    "q35 chipset layout, Red Hat PCI subsystem IDs on the chipset's devices"
                }
                MachineType::Pc => {
                    "i440FX chipset layout, Red Hat PCI subsystem IDs on the chipset's devices"
                }
            });
            if self.identity_enabled {
                // Without an identity the SMBIOS entry above says QEMU already.
                found.push("QEMU's ACPI tables to root (BXPC creator ID, fw_cfg in the DSDT)");
            }
        }
        found.push(self.uptime_giveaway(view.debian));
        found
    }

    /// What still tells a cloud profile from an instance of the provider.
    fn cloud_giveaways(&self, view: &VmView) -> Vec<&'static str> {
        let mut found =
            vec!["the QEMU/KVM hypervisor, visible by design as on the provider's machines"];
        if self.nat.network.is_empty() && view.has_card() {
            found.push("QEMU's default guest network (10.0.2.x)");
        }
        if view.network != VmNetwork::Routed {
            found.push("no metadata service: it answers only on a Routed network");
        }
        if self.cpu_passthrough {
            found.push(
                "the host CPU's family, model and feature flags behind the provider's CPU name",
            );
        }
        found.push(match view.display {
            Display::StdVga => {
                "the emulated display (QEMU's standard VGA), not the provider's Cirrus, QXL or Bochs"
            }
            Display::VirtioVga | Display::VirtioGpu => {
                "the emulated display (virtio), not the provider's Cirrus, QXL or Bochs"
            }
        });
        found.extend([
            "PCI subsystem IDs and the provider's own PCI bridges and balloon device",
            "DNS servers inside the DHCP network, not the provider's",
            "no provider agent process runs (files and stubs only)",
        ]);
        found.push(self.uptime_giveaway(view.debian));
        found
    }

    /// What the boot's age leaves visible: a fresh boot, or the traces of its
    /// clock model (docs/implementation/bases-and-stealth.md, "Aged uptime").
    fn uptime_giveaway(&self, debian: bool) -> &'static str {
        if self.boot_age_s == 0 {
            return "a fresh boot: minutes of uptime";
        }
        match (self.resolved_clock(debian), BootAge::of(self), debian) {
            (ClockModel::Continuous, _, true) => {
                "the boot age's step to the present at the first launch: systemd's watchdogs \
                 kill journald, udevd and logind for a timeout (in the journal; logind drops \
                 its sessions), and processes started at boot see their clocks jump; input \
                 and display event timestamps keep the kernel's monotonic clock"
            }
            (ClockModel::Continuous, _, false) => {
                "the boot age's step to the present at the first launch: processes started at \
                 boot see their clocks jump; input and display event timestamps keep the \
                 kernel's monotonic clock"
            }
            (_, BootAge::Server, _) => {
                "a server that slept for most of its uptime: CLOCK_BOOTTIME is ahead of \
                 CLOCK_MONOTONIC by the age, the kernel log's timestamps not counting it, and \
                 no suspend in the log or /sys/power/suspend_stats"
            }
            _ => {
                "the boot age is a sleep: CLOCK_BOOTTIME ahead of CLOCK_MONOTONIC, the kernel \
                 log's timestamps not counting it, and no suspend in the log or \
                 /sys/power/suspend_stats"
            }
        }
    }
}

fn display_text(display: Display) -> &'static str {
    match display {
        Display::StdVga => "the display is QEMU's standard VGA (Bochs)",
        Display::VirtioVga => "the display is virtio-vga (Red Hat vendor ID)",
        Display::VirtioGpu => "the display is virtio-gpu (Red Hat vendor ID)",
    }
}
