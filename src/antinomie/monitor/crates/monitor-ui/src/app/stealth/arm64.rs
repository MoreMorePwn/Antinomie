// SPDX-License-Identifier: GPL-3.0-only
//! The Device profile window for a VM on an arm64 base: the arm64 machine it
//! presents (picked by the preset and the VM's UUID, or chosen here) instead
//! of the PC catalog, and that machine's CPU instead of the x86 CPU settings.
use super::*;
use antinomie_monitor_core::stealth::{arm64, ArmKind, ArmMachine, ARM_MACHINES};

/// The picker's label of the machine the preset picks by itself.
const AUTOMATIC: &str = "By the preset, from the VM's UUID";

/// Whether `profile` names one machine of the arm64 catalog.
fn pinned(profile: &StealthProfile) -> Option<&'static ArmMachine> {
    ARM_MACHINES
        .iter()
        .find(|machine| machine.id == profile.identity.profile)
}

/// Pin `machine`: a board boots on its device tree (no UEFI), every other
/// machine through UEFI.
pub(super) fn choose(profile: &mut StealthProfile, machine: &ArmMachine) {
    profile.identity_enabled = true;
    profile.identity.profile = machine.id.into();
    if machine.tree.is_some() {
        profile.firmware = Firmware::Bios;
    } else if !profile.firmware.is_uefi() {
        profile.firmware = Firmware::Uefi;
    }
}

/// The Hardware identity section: which arm64 machine the VM presents.
/// `uefi`: the VM can boot UEFI (its base supports it and AAVMF is here).
pub(super) fn hardware(ui: &mut egui::Ui, profile: &mut StealthProfile, uefi: bool) {
    egui::Grid::new("vm_stealth_arm_machine")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            ui.label("Machine");
            let current = if !profile.identity_enabled {
                "QEMU's own (virt)".to_owned()
            } else {
                pinned(profile).map_or(AUTOMATIC.to_owned(), |machine| machine.label.into())
            };
            egui::ComboBox::from_id_salt("vm_stealth_arm_machine_combo")
                .selected_text(current)
                .width(260.0)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(
                            profile.identity_enabled && pinned(profile).is_none(),
                            AUTOMATIC,
                        )
                        .on_hover_text(
                            "A machine of the preset's kind, the same one for the VM's life",
                        )
                        .clicked()
                    {
                        profile.identity_enabled = true;
                        if pinned(profile).is_some() {
                            profile.identity.profile.clear();
                        }
                    }
                    for machine in ARM_MACHINES {
                        let label = format!("{} ({})", machine.label, machine.kind.label());
                        if ui
                            .selectable_label(
                                profile.identity_enabled && profile.identity.profile == machine.id,
                                label,
                            )
                            .clicked()
                        {
                            choose(profile, machine);
                        }
                    }
                    if ui
                        .selectable_label(!profile.identity_enabled, "QEMU's own (virt)")
                        .clicked()
                    {
                        profile.identity_enabled = false;
                    }
                });
            ui.end_row();
        });
    match arm64::presented(profile, uefi) {
        Some(machine) => {
            ui.label(format!("Shown as: {}", machine.label));
            let wanted = arm64::arm_machine(profile);
            if wanted.is_some_and(|wanted| wanted.id != machine.id) {
                ui.colored_label(
                    theme::warn(),
                    format!(
                        "{} boots UEFI, which this VM cannot (its base or AAVMF), so it is \
                         shown as this board on its device tree.",
                        wanted.map_or("", |wanted| wanted.label)
                    ),
                );
            }
            ui.colored_label(
                theme::muted(),
                if machine.kind == ArmKind::Board {
                    "The board's model, compatible names and serial number in a device tree \
                     without QEMU's virt nodes."
                } else {
                    "Its SMBIOS tables, ACPI OEM IDs, CPU, network card and disk, filled \
                     from the catalog and the VM's UUID; the PC fields do not apply to arm64."
                },
            );
            if ui
                .button("Randomize serials")
                .on_hover_text("New serials, UUID and MAC address (an automatic pick may change)")
                .clicked()
            {
                profile.identity.rerandomize();
                profile.new_mac();
            }
        }
        None => {
            ui.colored_label(
                theme::muted(),
                "QEMU's own identity: linux,dummy-virt and the virt machine's devices.",
            );
        }
    }
}

/// The CPU section: the presented machine's CPU, which an arm64 VM always
/// shows; the x86 settings (hypervisor flag, KVM signature, models) do not apply.
pub(super) fn cpu(ui: &mut egui::Ui, profile: &StealthProfile, uefi: bool) {
    match arm64::presented(profile, uefi) {
        Some(machine) => {
            ui.label(format!("{} ({})", machine.cpu_version, machine.cpu));
            ui.colored_label(
                theme::muted(),
                format!(
                    "MIDR 0x{:08x}, generic timer at {} MHz, one thread per core.",
                    machine.midr,
                    machine.cntfrq_hz / 1_000_000
                ),
            );
        }
        None => {
            ui.label("QEMU's emulated CPU (the VM's CPU model setting)");
        }
    }
    ui.colored_label(
        theme::muted(),
        "An arm64 VM's CPU is its machine's: the x86 CPU settings do not apply.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_board_boots_its_device_tree_and_a_server_uefi() {
        let mut profile =
            StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
        profile.identity.system_uuid = "4c4c4544-0042-3510-8051-b4c04f4e4a32".into();
        let board = ARM_MACHINES
            .iter()
            .find(|machine| machine.kind == ArmKind::Board)
            .unwrap();
        choose(&mut profile, board);
        assert_eq!(profile.firmware, Firmware::Bios);
        assert_eq!(arm64::presented(&profile, true).unwrap().id, board.id);
        let server = ARM_MACHINES
            .iter()
            .find(|machine| machine.kind == ArmKind::Server)
            .unwrap();
        choose(&mut profile, server);
        assert!(profile.firmware.is_uefi());
        assert_eq!(arm64::presented(&profile, true).unwrap().id, server.id);
        // Without UEFI the server is shown as a board.
        assert_eq!(
            arm64::presented(&profile, false).unwrap().kind,
            ArmKind::Board
        );
    }
}
