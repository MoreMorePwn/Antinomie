// SPDX-License-Identifier: GPL-3.0-only
//! Cloud-profile launch advice without changing a saved network policy.
use crate::theme;
use antinomie_monitor_core::{VmConfig, VmNetwork};
use eframe::egui;

pub(in crate::app) fn launch_advice(ui: &mut egui::Ui, vm: &mut VmConfig) {
    let (_, note) = vm.stealth.machine.for_ram(u64::from(vm.ram_mib) << 20);
    if let Some(note) = note {
        crate::activity::warning(ui, note);
    }
    if vm.stealth.cloud_provider().is_none() {
        return;
    }
    ui.label(
        egui::RichText::new(
            "Independent cloud simulation; no provider affiliation or endorsement.",
        )
        .small()
        .color(theme::muted()),
    );
    if vm.network() != VmNetwork::Routed {
        crate::activity::warning(
            ui,
            "Cloud metadata is unavailable on this network. Use Routed to enable the local simulated metadata service.",
        );
        if ui.button("Use Routed for cloud metadata").clicked() {
            // Only an explicit click changes the policy, including on saved VMs.
            vm.nat = false;
            vm.isolated_network = false;
            vm.routed = true;
        }
    } else {
        ui.label(
            egui::RichText::new(
                "Simulated cloud metadata is available locally; each run chooses its route.",
            )
            .small()
            .color(theme::muted()),
        );
    }
}
