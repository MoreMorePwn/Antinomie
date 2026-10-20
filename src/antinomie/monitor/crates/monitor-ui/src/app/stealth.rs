// SPDX-License-Identifier: MIT
//! VM configuration > Stealth profile: the hardware identity a VM shows its
//! guest. A preset fills every entry; editing one makes the profile Custom.
use super::*;
use antinomie_monitor_core::stealth::{
    chassis_label, host_cpu_vendor, MachineIdentity, NicModel, StealthPreset, StealthProfile,
    CHASSIS, MACHINES,
};

/// Picks a preset, applying it to every entry.
fn preset_combo(ui: &mut egui::Ui, profile: &mut StealthProfile, id: &str) {
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

/// The row in the VM dialog: the preset and the window.
pub(super) fn preset_row(ui: &mut egui::Ui, profile: &mut StealthProfile, open: &mut bool) {
    ui.label("Stealth");
    ui.horizontal(|ui| {
        preset_combo(ui, profile, "vm_stealth_preset");
        if ui
            .button("Edit…")
            .on_hover_text("Machine identity, CPU, network card and devices")
            .clicked()
        {
            *open = !*open;
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
                    .map_or("Custom fields", |machine| machine.label)
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

fn firmware(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    egui::Grid::new("vm_stealth_firmware")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Firmware");
            ui.label(RichText::new("SeaBIOS").color(theme::muted()))
                .on_hover_text("The firmware's own strings follow the BIOS fields above");
            ui.end_row();
            if profile.identity_enabled {
                text_row(ui, "ACPI OEM ID", &mut profile.identity.acpi_oem_id);
                text_row(ui, "ACPI table ID", &mut profile.identity.acpi_table_id);
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
        });
}

fn cpu(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    ui.checkbox(
        &mut profile.cpu_passthrough,
        "Pass the host CPU through (its real name and features)",
    )
    .on_hover_text("Needs KVM; without it the model is named after the host CPU");
    ui.checkbox(&mut profile.hide_hypervisor, "Hide the hypervisor CPU flag");
    ui.checkbox(&mut profile.hide_kvm, "Hide the KVM signature")
        .on_hover_text(
            "The guest then uses its TSC instead of kvm-clock: a small timekeeping cost",
        );
    ui.checkbox(&mut profile.pmu, "Performance counters");
    ui.checkbox(&mut profile.realistic_topology, "One socket with N cores");
    ui.add_enabled(
        profile.cpu_passthrough,
        egui::Checkbox::new(&mut profile.host_cache_info, "The host's cache sizes"),
    )
    .on_hover_text("QEMU otherwise reports its own cache sizes; passthrough only");
}

fn network(ui: &mut egui::Ui, profile: &mut StealthProfile) {
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
    if profile.nic != NicModel::VirtioNet {
        ui.colored_label(theme::muted(), "Emulated cards are slower than virtio-net.");
    }
    ui.colored_label(
        theme::muted(),
        "A network card exists only when the VM's network is Isolated or NAT.",
    );
}

fn storage(ui: &mut egui::Ui, profile: &mut StealthProfile) {
    egui::Grid::new("vm_stealth_storage")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Disk bus");
            ui.label(RichText::new("virtio").color(theme::muted()))
                .on_hover_text(
                    "SATA and NVMe need the guest kernel to have those drivers built in; \
                 the current bases boot from virtio only",
                );
            ui.end_row();
            if profile.identity_enabled {
                text_row(ui, "Disk serial", &mut profile.identity.disk_serial);
                text_row(ui, "CD-ROM model", &mut profile.identity.cdrom_model);
            }
        });
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

/// The Stealth profile window beside the VM dialog.
pub(super) fn window(
    ctx: &egui::Context,
    open: &mut bool,
    profile: &mut StealthProfile,
    editable: bool,
    creating: bool,
) {
    let mut closed = false;
    crate::widgets::window("Stealth profile")
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
                egui::ScrollArea::vertical()
                    .id_salt("vm_stealth_scroll")
                    .max_height((ctx.screen_rect().height() - 260.0).max(120.0))
                    .show(ui, |ui| {
                        egui::CollapsingHeader::new("Hardware identity")
                            .default_open(true)
                            .show(ui, |ui| hardware(ui, profile));
                        egui::CollapsingHeader::new("Firmware and ACPI")
                            .show(ui, |ui| firmware(ui, profile));
                        egui::CollapsingHeader::new("CPU").show(ui, |ui| cpu(ui, profile));
                        egui::CollapsingHeader::new("Network").show(ui, |ui| network(ui, profile));
                        egui::CollapsingHeader::new("Storage and devices")
                            .show(ui, |ui| storage(ui, profile));
                        egui::CollapsingHeader::new("Clock").show(ui, |ui| {
                            ui.checkbox(
                                &mut profile.rtc_localtime,
                                "Real-time clock in local time",
                            )
                            .on_hover_text("Linux PCs keep it in UTC; Windows PCs in local time");
                        });
                        egui::CollapsingHeader::new("Still visible").show(ui, |ui| {
                            for giveaway in profile.giveaways() {
                                ui.label(format!("• {giveaway}"));
                            }
                            ui.colored_label(
                                theme::muted(),
                                "The guest kernel's Antinomie options and build string, the fw_cfg \
                                 device and timing are outside launch options.",
                            );
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
