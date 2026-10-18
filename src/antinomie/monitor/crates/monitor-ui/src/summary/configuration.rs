// SPDX-License-Identifier: MIT
//! Configured capacities and launch preferences for the selected VM.
use super::*;

pub(super) fn show(ui: &mut egui::Ui, vm: &VmConfig, snapshot: &Snapshot) {
    ui.strong("VM configuration");
    let base = crate::app::selected_base(snapshot, vm.base_identity.as_deref())
        .map(|base| base.label.clone())
        .unwrap_or_else(|| {
            vm.base_identity
                .clone()
                .unwrap_or_else(|| "Default base".into())
        });
    let rows = [
        (
            "CPU",
            format!("{} vCPU · {}", vm.cpus, vm.launch.cpu_model.label()),
        ),
        ("RAM", format!("{} MiB", vm.ram_mib)),
        ("Disk capacity", format!("{} GiB", vm.disk_gib)),
        ("Network", network_label(vm).to_owned()),
        ("Acceleration", vm.launch.acceleration.label().to_owned()),
        (
            "Display",
            format!(
                "{}{}{}",
                vm.launch.resolution.label(),
                if vm.launch.fullscreen {
                    " · Fullscreen"
                } else {
                    ""
                },
                if vm.launch.fit_to_window {
                    " · Fit to window"
                } else {
                    ""
                }
            ),
        ),
        ("Base image", base),
        (
            "Transport",
            format!(
                "{} KiB per vCPU · {} µs send wait",
                vm.transport.ring_kib,
                vm.transport.send_wait_us()
            ),
        ),
    ];
    let label_width = (ui.available_width() * 0.38).min(190.0);
    for (name, value) in rows {
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(label_width, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.add(egui::Label::new(RichText::new(name).color(theme::muted())).wrap());
                },
            );
            ui.add(egui::Label::new(value).wrap());
        });
    }
}
