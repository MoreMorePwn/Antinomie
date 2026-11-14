// SPDX-License-Identifier: GPL-3.0-only
//! The Device profile's preset and cloud provider lists: a picked preset
//! applies to every entry (an arm64 VM draws no uptime), and each list has
//! one help icon that names its choices.
use super::*;

/// Picks a preset, applying it to every entry, and a cloud's provider beside it.
pub(super) fn preset_combo(
    ui: &mut egui::Ui,
    profile: &mut StealthProfile,
    id: &str,
    arch: GuestArch,
) {
    preset_list(ui, profile, id, arch);
    provider_list(ui, profile, id, arch);
}

/// The presets for a VM of `arch`; one it cannot present (the IoT device on
/// x86-64) is listed disabled with the reason.
pub(super) fn preset_list(
    ui: &mut egui::Ui,
    profile: &mut StealthProfile,
    id: &str,
    arch: GuestArch,
) {
    let mut preset = profile.preset;
    let presets = crate::widgets::list_help(
        "Presets",
        // Each description names what it needs (the IoT device: arm64
        // only); the list shows the unavailable one disabled with the reason.
        StealthPreset::ALL
            .iter()
            .map(|option| (option.label(), option.description())),
    );
    // One row (the dialog draws it in a grid cell): the list and its help.
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt(id)
            .selected_text(preset.label())
            .width(260.0)
            .truncate()
            // Every preset without scrolling.
            .height(400.0)
            .show_ui(ui, |ui| {
                for &option in StealthPreset::ALL {
                    let reason = option.unavailable(arch);
                    let response = ui.add_enabled(
                        reason.is_none(),
                        egui::Button::selectable(preset == option, option.label()),
                    );
                    match reason {
                        Some(reason) => {
                            response.reason_tip(format!("{} ({reason})", option.description()));
                        }
                        None => {
                            if response.clicked() {
                                preset = option;
                            }
                        }
                    }
                }
            });
        help(ui, presets);
    });
    if preset != profile.preset {
        // An arm64 VM draws no uptime (its guest ignores one for now).
        *profile = profile
            .for_preset(preset, &host_cpu_vendor())
            .drawn_for(arch);
    }
}

/// The provider of a Cloud VPS profile; nothing for any other.
pub(super) fn provider_list(
    ui: &mut egui::Ui,
    profile: &mut StealthProfile,
    id: &str,
    arch: GuestArch,
) {
    if profile.preset == StealthPreset::CloudVps
        && let Some(current) = profile.cloud_provider()
    {
        let mut picked = current;
        egui::ComboBox::from_id_salt(format!("{id}_cloud"))
            .selected_text(current.label)
            .width(260.0)
            .truncate()
            .show_ui(ui, |ui| {
                for provider in CLOUDS {
                    ui.selectable_value(&mut picked, provider, provider.label);
                }
            });
        if picked.id != current.id {
            *profile = StealthProfile::cloud_vps(picked).drawn_for(arch);
        }
    }
}
