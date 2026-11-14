// SPDX-License-Identifier: GPL-3.0-only
//! Cloud-profile launch advice without changing a saved network policy.
use crate::theme;
use antinomie_monitor_core::{stealth::MACHINES, VmConfig, VmNetwork};
use eframe::egui;

/// What the Routed button does and why (its help icon).
pub(in crate::app) const ROUTED_HELP: &str =
    "A real cloud instance can ask its provider's metadata service (169.254.169.254 and the \
     like) for its identity and credentials, and malware may check that it answers. Cloud \
     VPS answers it with fake data and canary credentials from Antinomie's route gateway, \
     which only a Routed network has.\n\nThis button sets the VM's Network to Routed, as \
     choosing it under Network does; it applies when you create or save the VM. Each run \
     then picks its route.";

pub(in crate::app) fn launch_advice(ui: &mut egui::Ui, vm: &mut VmConfig) {
    let (_, note) = vm.stealth.machine.for_ram(u64::from(vm.ram_mib) << 20);
    if let Some(note) = note {
        crate::activity::info(ui, note);
    }
    if vm.stealth.cloud_provider().is_none() {
        if vm.stealth.identity_enabled
            && MACHINES
                .iter()
                .any(|machine| machine.id == vm.stealth.identity.profile)
        {
            ui.label(
                egui::RichText::new(
                    "Independent imitation of a real machine's reported identity; no affiliation with or endorsement by its maker.",
                )
                .small()
                .color(theme::muted()),
            );
        }
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
        crate::activity::info(
            ui,
            "Cloud metadata service is off: it needs a Routed network. Set Network to Routed to turn it on.",
        );
        let clicked = ui
            .horizontal(|ui| {
                let clicked = ui.button("Use Routed for cloud metadata").clicked();
                super::help(ui, ROUTED_HELP);
                clicked
            })
            .inner;
        if clicked {
            // Only an explicit click changes the policy, including on saved VMs.
            vm.nat = false;
            vm.isolated_network = false;
            vm.routed = true;
        }
    } else {
        ui.label(
            egui::RichText::new(
                "Fake cloud metadata with canary credentials is served inside the VM only; each run chooses its route.",
            )
            .small()
            .color(theme::muted()),
        );
    }
}
