// SPDX-License-Identifier: GPL-3.0-only
//! VM configuration > Device profile: the hardware identity a VM shows its
//! guest. A preset fills every entry; editing one makes the profile Custom.
use super::*;
mod cloud;
use antinomie_monitor_core::stealth::{
    base_supporting, chassis_label, disk_bus_unavailable, firmware_unavailable, host_cpu_vendor,
    BaseSupport, DiskBus, DiskMedia, Fallback, FallbackSetting, Firmware, HostSupport,
    MachineIdentity, NatNetwork, NicModel, Pointer, RtcClock, SmbiosEntry, StealthPreset,
    StealthProfile, CHASSIS, CLOUDS, CPU_MODELS, MACHINES,
};
pub(super) use cloud::launch_advice;

/// What the host offers (OVMF, clean SMT), read once.
pub(super) fn host_support() -> &'static HostSupport {
    HostSupport::cached()
}

/// A combo box whose unavailable choices are shown disabled with the reason.
fn choice<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut T,
    options: &[T],
    label: impl Fn(T) -> &'static str,
    unavailable: impl Fn(T) -> Option<String>,
) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(label(*value))
        .width(260.0)
        .show_ui(ui, |ui| {
            for &option in options {
                let reason = unavailable(option);
                let response = ui.add_enabled(
                    reason.is_none(),
                    egui::SelectableLabel::new(*value == option, label(option)),
                );
                if let Some(reason) = reason {
                    response.on_disabled_hover_text(reason);
                } else if response.clicked() {
                    *value = option;
                }
            }
        });
}

impl MonitorApp {
    /// What a VM's device profile asks for that its base or this host cannot
    /// give: the settings that fall back when it starts.
    pub(crate) fn stealth_fallbacks_of(&self, vm: &VmConfig) -> Vec<Fallback> {
        antinomie_monitor_core::stealth::vm_fallbacks(vm, &self.snapshot.bases, host_support())
    }

    pub(super) fn draft_stealth_fallbacks(&self) -> Vec<Fallback> {
        self.stealth_fallbacks_of(&self.draft)
    }
}

/// What the VM's base and this host cannot give of the profile, for the
/// window: each difference is shown on its own setting, with a switch to an
/// installed base that supports it.
pub(super) struct Fit<'a> {
    pub base: BaseSupport,
    fallbacks: Vec<Fallback>,
    bases: &'a [BaseSummary],
    current: Option<&'a str>,
    /// A base the user chose to switch the VM to.
    pub switch: Option<String>,
}

impl<'a> Fit<'a> {
    pub(super) fn new(
        profile: &StealthProfile,
        base: BaseSupport,
        bases: &'a [BaseSummary],
        current: Option<&'a str>,
    ) -> Self {
        Self {
            fallbacks: profile.fallbacks(&base, host_support()),
            base,
            bases,
            current,
            switch: None,
        }
    }

    /// The line on a setting that fell back, in a form grid: under the setting.
    fn row(&mut self, ui: &mut egui::Ui, profile: &StealthProfile, setting: FallbackSetting) {
        if self
            .fallbacks
            .iter()
            .all(|fallback| fallback.setting != setting)
        {
            return;
        }
        ui.label("");
        ui.vertical(|ui| self.line(ui, profile, setting));
        ui.end_row();
    }

    /// The same line outside a grid.
    fn line(&mut self, ui: &mut egui::Ui, profile: &StealthProfile, setting: FallbackSetting) {
        let Some(fallback) = self.fallbacks.iter().find(|f| f.setting == setting) else {
            return;
        };
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} {}",
                    egui_phosphor::regular::WARNING,
                    fallback.summary
                ))
                .color(theme::warn()),
            )
            .wrap(),
        )
        .on_hover_text(&fallback.reason);
        ui.add(
            egui::Label::new(
                RichText::new(&fallback.reason)
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
        if let Some(base) =
            base_supporting(profile, setting, self.current, self.bases, host_support())
            && ui
                .button(format!("Use base {}", base.label))
                .on_hover_text("Switch this VM to an installed base that supports the setting")
                .clicked()
        {
            self.switch = Some(base.id.clone());
        }
    }

    /// The top of the window: every setting that will not be applied, where it
    /// is not hidden in a closed section.
    fn summary(&self, ui: &mut egui::Ui) {
        if self.fallbacks.is_empty() {
            return;
        }
        crate::activity::warning(
            ui,
            format!(
                "{} setting{} will not be applied as chosen:\n{}",
                self.fallbacks.len(),
                if self.fallbacks.len() == 1 { "" } else { "s" },
                self.fallbacks
                    .iter()
                    .map(|fallback| format!("• {}", fallback.summary))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        );
    }
}

/// Picks a preset, applying it to every entry, and a cloud's provider beside it.
fn preset_combo(ui: &mut egui::Ui, profile: &mut StealthProfile, id: &str) {
    preset_list(ui, profile, id);
    provider_list(ui, profile, id);
}

fn preset_list(ui: &mut egui::Ui, profile: &mut StealthProfile, id: &str) {
    let mut preset = profile.preset;
    egui::ComboBox::from_id_salt(id)
        .selected_text(preset.label())
        .width(260.0)
        .show_ui(ui, |ui| {
            for &option in StealthPreset::ALL {
                ui.selectable_value(&mut preset, option, option.label());
            }
        });
    if preset != profile.preset {
        *profile = profile.for_preset(preset, &host_cpu_vendor());
    }
}

/// The provider of a Cloud VPS profile; nothing for any other.
fn provider_list(ui: &mut egui::Ui, profile: &mut StealthProfile, id: &str) {
    if profile.preset == StealthPreset::CloudVps
        && let Some(current) = profile.cloud_provider()
    {
        let mut picked = current;
        egui::ComboBox::from_id_salt(format!("{id}_cloud"))
            .selected_text(current.label)
            .width(260.0)
            .show_ui(ui, |ui| {
                for provider in CLOUDS {
                    ui.selectable_value(&mut picked, provider, provider.label);
                }
            });
        if picked.id != current.id {
            *profile = StealthProfile::cloud_vps(picked);
        }
    }
}

/// The row in the VM dialog: the preset and the window.
pub(super) fn preset_row(
    ui: &mut egui::Ui,
    profile: &mut StealthProfile,
    open: &mut bool,
    fallbacks: &[Fallback],
) {
    // The provider's list has a row of its own, so the form keeps the width
    // of one list whichever profile is chosen.
    ui.horizontal_wrapped(|ui| {
        ui.label("Device profile");
        ui.label(RichText::new(egui_phosphor::regular::QUESTION).color(theme::muted()))
            .on_hover_text("Could be helpful for handling anti-VM or anti-sandbox checks.");
    });
    preset_list(ui, profile, "vm_stealth_preset");
    ui.end_row();
    if profile.preset == StealthPreset::CloudVps {
        ui.label("");
        provider_list(ui, profile, "vm_stealth_preset");
        ui.end_row();
    }
    ui.label("");
    ui.horizontal_wrapped(|ui| {
        if ui
            .button("Edit…")
            .on_hover_text("Machine identity, CPU, network card and devices")
            .clicked()
        {
            *open = !*open;
        }
        if !fallbacks.is_empty() {
            ui.colored_label(
                theme::warn(),
                format!(
                    "{} {} {}",
                    egui_phosphor::regular::WARNING,
                    fallbacks.len(),
                    if fallbacks.len() == 1 {
                        "setting falls back"
                    } else {
                        "settings fall back"
                    }
                ),
            )
            .on_hover_text(
                fallbacks
                    .iter()
                    .map(|fallback| fallback.summary.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
    });
    ui.end_row();
}

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(260.0));
    ui.end_row();
}

fn identity_fields(ui: &mut egui::Ui, identity: &mut MachineIdentity) {
    egui::Grid::new("vm_stealth_fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            text_row(ui, "BIOS vendor", &mut identity.bios_vendor);
            text_row(ui, "BIOS version", &mut identity.bios_version);
            text_row(ui, "BIOS date", &mut identity.bios_date);
            text_row(ui, "System maker", &mut identity.system_manufacturer);
            text_row(ui, "Product", &mut identity.system_product);
            text_row(ui, "Version", &mut identity.system_version);
            text_row(ui, "Family", &mut identity.system_family);
            text_row(ui, "SKU", &mut identity.system_sku);
            text_row(ui, "Serial", &mut identity.system_serial);
            text_row(ui, "UUID", &mut identity.system_uuid);
            text_row(ui, "Board maker", &mut identity.board_manufacturer);
            text_row(ui, "Board", &mut identity.board_product);
            text_row(ui, "Board serial", &mut identity.board_serial);
            text_row(ui, "Chassis serial", &mut identity.chassis_serial);
            text_row(ui, "Memory maker", &mut identity.memory_manufacturer);
            text_row(ui, "Memory part", &mut identity.memory_part);
            text_row(ui, "Memory serial", &mut identity.memory_serial);
        });
}

/// SMBIOS type 11 strings, one per line.
fn oem_strings(ui: &mut egui::Ui, identity: &mut MachineIdentity) {
    ui.label("OEM strings");
    let mut text = identity.oem_strings.join("\n");
    if ui
        .add(
            egui::TextEdit::multiline(&mut text)
                .desired_rows(3)
                .desired_width(260.0),
        )
        .on_hover_text("SMBIOS type 11, one string per line; PC firmware fills it, QEMU does not")
        .changed()
    {
        identity.oem_strings = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
    }
    ui.end_row();
}

fn hardware(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    egui::Grid::new("vm_stealth_machine")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Machine");
            let current = if profile.identity_enabled {
                MACHINES
                    .iter()
                    .find(|machine| machine.id == profile.identity.profile)
                    .map(|machine| machine.label)
                    .or_else(|| profile.cloud_provider().map(|provider| provider.label))
                    .unwrap_or("Custom fields")
            } else {
                "QEMU default"
            };
            egui::ComboBox::from_id_salt("vm_stealth_machine_combo")
                .selected_text(current)
                .width(260.0)
                .show_ui(ui, |ui| {
                    for machine in MACHINES {
                        let label = format!(
                            "{} ({})",
                            machine.label,
                            if machine.cpu_vendor == "AuthenticAMD" {
                                "AMD"
                            } else {
                                "Intel"
                            }
                        );
                        if ui
                            .selectable_label(
                                profile.identity_enabled && profile.identity.profile == machine.id,
                                label,
                            )
                            .clicked()
                        {
                            profile.use_machine(machine);
                        }
                    }
                    if ui
                        .selectable_label(!profile.identity_enabled, "QEMU default")
                        .clicked()
                    {
                        profile.identity_enabled = false;
                    }
                });
            ui.end_row();
            if profile.identity_enabled {
                ui.label("Chassis");
                let chassis = chassis_label(profile.identity.chassis_type);
                egui::ComboBox::from_id_salt("vm_stealth_chassis")
                    .selected_text(chassis)
                    .width(260.0)
                    .show_ui(ui, |ui| {
                        for (kind, label) in CHASSIS {
                            ui.selectable_value(&mut profile.identity.chassis_type, *kind, *label);
                        }
                    });
                ui.end_row();
                text_row(ui, "Serial", &mut profile.identity.system_serial);
            }
        });
    if profile.identity_enabled {
        ui.horizontal(|ui| {
            if ui
                .button("Randomize serials")
                .on_hover_text("New serials, UUID, disk serial and MAC address")
                .clicked()
            {
                profile.identity.rerandomize();
                profile.new_mac();
            }
        });
        let host = host_cpu_vendor();
        if let Some(machine) = MACHINES
            .iter()
            .find(|machine| machine.id == profile.identity.profile)
        {
            if !host.is_empty() && machine.cpu_vendor != host && profile.cpu_passthrough {
                ui.colored_label(
                    theme::warn(),
                    "This machine never shipped with the host's CPU vendor, which passthrough shows.",
                );
            }
        }
        egui::CollapsingHeader::new("Edit fields…")
            .id_salt("vm_stealth_edit_fields")
            .show(ui, |ui| identity_fields(ui, &mut profile.identity));
    }
}

fn firmware(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    let base = fit.base;
    egui::Grid::new("vm_stealth_firmware")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Firmware");
            choice(
                ui,
                "vm_stealth_firmware_kind",
                &mut profile.firmware,
                Firmware::ALL,
                Firmware::label,
                |firmware| firmware_unavailable(firmware, &base, host_support()),
            );
            ui.end_row();
            fit.row(ui, profile, FallbackSetting::Firmware);
            if profile.firmware == Firmware::UefiSecureBoot {
                ui.label("");
                ui.colored_label(
                    theme::muted(),
                    "OVMF finds the kernel unsigned and starts it with its legacy loader; \
                     the guest sees Secure Boot on",
                );
                ui.end_row();
            }
            if profile.identity_enabled {
                text_row(ui, "ACPI OEM ID", &mut profile.identity.acpi_oem_id);
                text_row(ui, "ACPI table ID", &mut profile.identity.acpi_table_id);
                ui.label("SMBIOS entry");
                ui.horizontal(|ui| {
                    ui.radio_value(
                        &mut profile.smbios_entry,
                        SmbiosEntry::Bits64,
                        "64-bit (3.x)",
                    );
                    ui.radio_value(
                        &mut profile.smbios_entry,
                        SmbiosEntry::Bits32,
                        "32-bit (2.x)",
                    );
                });
                ui.end_row();
                oem_strings(ui, &mut profile.identity);
            }
            ui.label("Devices");
            ui.checkbox(&mut profile.hpet, "HPET timer");
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut profile.vmport, "VMware backdoor port")
                .on_hover_text("Only VMware VMs have it; real PCs do not");
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut profile.usb, "Intel ICH9 USB controllers")
                .on_hover_text("Every PC has USB; QEMU adds none by default");
            ui.end_row();
            ui.label("");
            let secure_boot = profile.firmware == Firmware::UefiSecureBoot;
            let mut smm = profile.smm || secure_boot;
            ui.add_enabled(
                !secure_boot,
                egui::Checkbox::new(&mut smm, "System management mode"),
            )
            .on_hover_text("PCs have SMM; Secure Boot firmware needs it")
            .on_disabled_hover_text("Secure Boot firmware keeps its variables in SMM");
            if !secure_boot {
                profile.smm = smm;
            }
            ui.end_row();
        });
}

fn cpu(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    ui.checkbox(
        &mut profile.cpu_passthrough,
        "Pass the host CPU through (its real name and features)",
    )
    .on_hover_text("Needs KVM; without it the model is named after the host CPU");
    if !profile.cpu_passthrough {
        egui::Grid::new("vm_stealth_cpu_model")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Model");
                let host = host_cpu_vendor();
                let current = if profile.cpu_model.is_empty() {
                    "The VM's CPU model setting".to_owned()
                } else {
                    profile.cpu_model.clone()
                };
                egui::ComboBox::from_id_salt("vm_stealth_cpu_named")
                    .selected_text(current)
                    .width(260.0)
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(
                                profile.cpu_model.is_empty(),
                                "The VM's CPU model setting",
                            )
                            .clicked()
                        {
                            profile.cpu_model.clear();
                            profile.cpu_brand.clear();
                        }
                        for model in CPU_MODELS
                            .iter()
                            .filter(|model| host.is_empty() || model.cpu_vendor == host)
                        {
                            if ui
                                .selectable_label(profile.cpu_model == model.model, model.model)
                                .on_hover_text(model.brand)
                                .clicked()
                            {
                                profile.cpu_model = model.model.into();
                                profile.cpu_brand = model.brand.into();
                            }
                        }
                    });
                ui.end_row();
                text_row(ui, "Brand string", &mut profile.cpu_brand);
                ui.label("");
                ui.add_enabled(
                    !profile.cpu_model.is_empty(),
                    egui::Checkbox::new(&mut profile.model_cache_info, "The model's own caches"),
                )
                .on_hover_text("Its real cache layout and an L3 instead of QEMU's legacy one");
                ui.end_row();
            });
    }
    ui.checkbox(&mut profile.hide_hypervisor, "Hide the hypervisor CPU flag");
    ui.checkbox(&mut profile.hide_kvm, "Hide the KVM signature")
        .on_hover_text(
            "The guest then uses its TSC instead of kvm-clock: a small timekeeping cost",
        );
    ui.add_enabled(
        !profile.hide_kvm,
        egui::Checkbox::new(&mut profile.kvm_clock, "kvm-clock"),
    )
    .on_hover_text("The guest's clock source while the KVM signature is shown")
    .on_disabled_hover_text("Hiding the KVM signature also hides kvm-clock");
    ui.checkbox(&mut profile.pmu, "Performance counters");
    ui.checkbox(&mut profile.realistic_topology, "One socket with N cores");
    let smt = &host_support().smt;
    ui.add_enabled(
        profile.realistic_topology && smt.is_ok(),
        egui::Checkbox::new(&mut profile.smt, "Two threads per core"),
    )
    .on_hover_text("As a CPU with SMT: N/2 cores of two threads (an even CPU count)")
    .on_disabled_hover_text(match smt {
        Err(reason) => reason.clone(),
        Ok(()) => "Needs one socket with N cores".to_owned(),
    });
    fit.line(ui, profile, FallbackSetting::Smt);
    ui.add_enabled(
        profile.cpu_passthrough,
        egui::Checkbox::new(&mut profile.host_cache_info, "The host's cache sizes"),
    )
    .on_hover_text("QEMU otherwise reports its own cache sizes; passthrough only");
}

fn network(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    egui::Grid::new("vm_stealth_network")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Card");
            let before = profile.nic;
            egui::ComboBox::from_id_salt("vm_stealth_nic")
                .selected_text(profile.nic.label())
                .width(260.0)
                .show_ui(ui, |ui| {
                    for &nic in NicModel::ALL {
                        ui.selectable_value(&mut profile.nic, nic, nic.label());
                    }
                });
            if profile.nic != before && !profile.mac.is_empty() {
                profile.new_mac();
            }
            ui.end_row();
            ui.label("MAC address");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut profile.mac)
                        .desired_width(150.0)
                        .hint_text(crate::theme::hint_text("52:54:00:12:34:56")),
                );
                if ui
                    .button("Random")
                    .on_hover_text("A random address with the card's vendor prefix")
                    .clicked()
                {
                    profile.new_mac();
                }
                if ui
                    .button("Local")
                    .on_hover_text("A random locally administered address, which names no vendor")
                    .clicked()
                {
                    profile.new_local_mac();
                }
                if ui.button("QEMU default").clicked() {
                    profile.mac.clear();
                }
            });
            ui.end_row();
        });
    ui.colored_label(
        theme::muted(),
        "A network card exists only when the VM's network is Isolated, NAT or Routed. The guest network applies to NAT and Routed.",
    );
    egui::Grid::new("vm_stealth_nat")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            if profile.identity_enabled && profile.nic == NicModel::E1000e {
                ui.label("Card subsystem");
                ui.add(
                    egui::TextEdit::singleline(&mut profile.identity.nic_subsystem)
                        .desired_width(150.0)
                        .hint_text(crate::theme::hint_text("8086:0000")),
                )
                .on_hover_text("A board's own card carries its maker's PCI subsystem IDs");
                ui.end_row();
            }
            ui.label("Guest network");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut profile.nat.network)
                        .desired_width(150.0)
                        .hint_text(crate::theme::hint_text("10.0.2.0/24")),
                );
                if ui
                    .button("Home")
                    .on_hover_text("192.168.1.0/24 behind a router at .1")
                    .clicked()
                {
                    profile.nat = NatNetwork::home();
                }
                if ui
                    .button("QEMU default")
                    .on_hover_text("10.0.2.0/24, which QEMU and VirtualBox share")
                    .clicked()
                {
                    profile.nat = NatNetwork::default();
                }
            });
            ui.end_row();
            if !profile.nat.network.is_empty() {
                text_row(ui, "Gateway", &mut profile.nat.gateway);
                text_row(ui, "DNS server", &mut profile.nat.dns);
                text_row(ui, "DHCP start", &mut profile.nat.dhcp_start);
                fit.row(ui, profile, FallbackSetting::Nat);
            }
        });
    if !profile.nat.network.is_empty() {
        ui.colored_label(
            theme::muted(),
            "The guest learns them by DHCP. QEMU needs the DNS server apart from the gateway; \
             an isolated VM's guest uses the gateway for both.",
        );
    }
}

fn storage(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    let base = fit.base;
    egui::Grid::new("vm_stealth_storage")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Disk bus");
            choice(
                ui,
                "vm_stealth_disk_bus",
                &mut profile.disk_bus,
                DiskBus::ALL,
                DiskBus::label,
                |bus| disk_bus_unavailable(bus, &base).map(str::to_owned),
            );
            ui.end_row();
            fit.row(ui, profile, FallbackSetting::DiskBus);
            if profile.disk_bus == DiskBus::Sata {
                ui.label("Disk kind");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut profile.disk_media, DiskMedia::Ssd, "SSD");
                    ui.radio_value(
                        &mut profile.disk_media,
                        DiskMedia::Hdd,
                        "Hard disk (7,200 rpm)",
                    );
                });
                ui.end_row();
            }
            if profile.identity_enabled {
                if profile.disk_bus == DiskBus::Sata {
                    text_row(ui, "Disk model", &mut profile.identity.disk_model);
                    text_row(ui, "Disk firmware", &mut profile.identity.disk_firmware);
                    text_row(ui, "Disk WWN", &mut profile.identity.disk_wwn);
                }
                text_row(ui, "Disk serial", &mut profile.identity.disk_serial);
            }
            ui.label("CD-ROM");
            ui.checkbox(&mut profile.cdrom, "An empty SATA CD-ROM drive")
                .on_hover_text(
                    "Desktops with an optical drive have one; QEMU's answers \
                     \"QEMU DVD-ROM\" to the SCSI inquiry whatever its model",
                );
            ui.end_row();
            if profile.identity_enabled && profile.cdrom {
                text_row(ui, "CD-ROM model", &mut profile.identity.cdrom_model);
            }
        });
    if profile.disk_bus == DiskBus::Nvme {
        ui.colored_label(
            theme::muted(),
            "QEMU's NVMe controller names itself \"QEMU NVMe Ctrl\" with QEMU's version as \
             firmware and an org.qemu subsystem name; only its serial and PCI vendor (Intel's) \
             can be set.",
        );
    }
    ui.colored_label(
        theme::muted(),
        "The disk's size is the VM's (pafish flags under 60 GiB).",
    );
}

fn display(ui: &mut egui::Ui, profile: &mut StealthProfile, fit: &mut Fit) {
    ui.label("Pointer");
    for &pointer in Pointer::ALL {
        let usable = pointer != Pointer::UsbTablet || profile.usb;
        ui.add_enabled_ui(usable, |ui| {
            ui.radio_value(&mut profile.pointer, pointer, pointer.label())
                .on_disabled_hover_text("Needs the Intel ICH9 USB controllers");
            ui.label(RichText::new(pointer.cost()).small().color(theme::muted()));
        });
    }
    fit.line(ui, profile, FallbackSetting::Pointer);
    ui.add_space(4.0);
    ui.colored_label(
        theme::muted(),
        "Display: virtio-gpu when the VM has a fixed resolution (Antinomie sizes its window \
         through it), QEMU's standard VGA otherwise. Both name a VM vendor.",
    );
}

fn clock(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    ui.checkbox(&mut profile.rtc_localtime, "Real-time clock in local time")
        .on_hover_text(
            "Linux PCs keep it in UTC and Linux guests read it as UTC; Windows PCs in local time",
        );
    ui.horizontal(|ui| {
        ui.label("Driven by");
        ui.radio_value(&mut profile.rtc_clock, RtcClock::Host, "the host's clock")
            .on_hover_text("Wall time goes on while the VM is paused");
        ui.radio_value(&mut profile.rtc_clock, RtcClock::Vm, "the VM's clock")
            .on_hover_text("Stops while the VM is paused, as if it had been off");
    });
    ui.checkbox(&mut profile.rtc_driftfix, "Catch up on missed clock ticks")
        .on_hover_text("For guests that count RTC interrupts (Windows); Linux does not need it");
}

/// A preset applied this frame stays that preset; any other edit is Custom.
pub(super) fn settle_preset(before: &StealthProfile, profile: &mut StealthProfile) {
    if profile != before
        && profile.preset == before.preset
        && profile.preset != StealthPreset::Custom
    {
        profile.preset = StealthPreset::Custom;
    }
}

/// The Device profile window beside the VM dialog.
pub(super) fn window(
    ctx: &egui::Context,
    open: &mut bool,
    profile: &mut StealthProfile,
    fit: &mut Fit,
    size_hints: &[&str],
    editable: bool,
    creating: bool,
) {
    let mut closed = false;
    crate::widgets::window("Device profile")
        .id(egui::Id::new("vm_stealth"))
        .pivot(egui::Align2::CENTER_TOP)
        .default_pos(egui::pos2(ctx.screen_rect().center().x, 60.0))
        .open(open)
        .collapsible(false)
        .resizable(true)
        .default_width(520.0)
        .max_height((ctx.screen_rect().height() - 100.0).max(200.0))
        .show(ctx, |ui| {
            let before = profile.clone();
            ui.add_enabled_ui(editable, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Preset");
                    preset_combo(ui, profile, "vm_stealth_window_preset");
                });
                fit.summary(ui);
                egui::ScrollArea::vertical()
                    .id_salt("vm_stealth_scroll")
                    .max_height((ctx.screen_rect().height() - 260.0).max(120.0))
                    .show(ui, |ui| {
                        egui::CollapsingHeader::new("Hardware identity")
                            .default_open(true)
                            .show(ui, |ui| hardware(ui, profile));
                        egui::CollapsingHeader::new("Firmware and ACPI")
                            .show(ui, |ui| firmware(ui, profile, fit));
                        egui::CollapsingHeader::new("CPU").show(ui, |ui| cpu(ui, profile, fit));
                        egui::CollapsingHeader::new("Network")
                            .show(ui, |ui| network(ui, profile, fit));
                        egui::CollapsingHeader::new("Storage and devices").show(ui, |ui| {
                            storage(ui, profile, fit);
                            ui.add_space(6.0);
                            display(ui, profile, fit);
                        });
                        egui::CollapsingHeader::new("Clock").show(ui, |ui| clock(ui, profile));
                        egui::CollapsingHeader::new("Still visible").show(ui, |ui| {
                            let (fitted, notes) = profile.fitted(&fit.base, host_support());
                            for giveaway in fitted.giveaways() {
                                ui.label(format!("• {giveaway}"));
                            }
                            for note in notes {
                                ui.colored_label(theme::warn(), format!("• {note}"));
                            }
                            // The VM's own settings, which pafish-style checks read.
                            for hint in size_hints {
                                ui.colored_label(theme::warn(), format!("• The VM's size: {hint}"));
                            }
                        });
                    });
            });
            settle_preset(&before, profile);
            if let Err(error) = profile.validate() {
                ui.colored_label(theme::error(), error);
            }
            if !editable {
                crate::activity::warning(ui, "Stop the VM to change its hardware.");
            } else if !creating {
                crate::activity::warning(
                    ui,
                    "Snapshots saved with other hardware may not restore after a change.",
                );
            }
            let mut close = false;
            dialog_footer(ui, |ui| {
                close = ui.button("Done").clicked();
                ui.label(
                    RichText::new("Save the VM configuration to apply.").color(theme::muted()),
                );
            });
            closed = close;
        });
    if closed {
        *open = false;
    }
}
