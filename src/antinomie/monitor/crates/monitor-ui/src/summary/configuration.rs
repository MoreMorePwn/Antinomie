// SPDX-License-Identifier: MIT
//! Configured capacities, launch preferences and the stealth profile of the
//! selected VM, as cards.
use super::*;
use antinomie_monitor_core::stealth::{
    chassis_label, DiskBus, Firmware, StealthPreset, StealthProfile, MACHINES,
};
use egui_phosphor::regular as icon;

/// Set for one frame when Configure… is pressed; the app opens the dialog.
pub(crate) const CONFIGURE: &str = "summary_configure_vm";

pub(super) fn show(ui: &mut egui::Ui, vm: &VmConfig, snapshot: &Snapshot) {
    let width = ui.available_width();
    let running = snapshot.active_vm.as_deref() == Some(vm.id.as_str());
    ui.horizontal(|ui| {
        ui.strong("VM configuration");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let button = ui
                .add_enabled(
                    !running,
                    egui::Button::new(format!("{} Configure…", icon::SLIDERS_HORIZONTAL)),
                )
                .on_disabled_hover_text("Stop the VM to change its configuration");
            if button.clicked() {
                ui.ctx()
                    .data_mut(|data| data.insert_temp(egui::Id::new(CONFIGURE), true));
            }
        });
    });
    ui.add_space(4.0);
    let narrow = width < ui.text_style_height(&egui::TextStyle::Body) * 32.0;
    let columns = if narrow { 1 } else { 3 };
    let card_width = ((width - 10.0 * (columns as f32 - 1.0)) / columns as f32).max(80.0);
    resource_cards(
        ui,
        "summary-configuration",
        3,
        columns,
        card_width,
        10,
        |ui, slot| match slot {
            0 => compute(ui, vm),
            1 => storage(ui, vm, snapshot),
            _ => network(ui, vm),
        },
    );
    ui.add_space(10.0);
    resource_cards(ui, "summary-stealth", 1, 1, width.max(80.0), 10, |ui, _| {
        stealth(ui, &vm.stealth, narrow)
    });
}

fn title(ui: &mut egui::Ui, symbol: &str, text: &str, color: Color32) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(symbol).size(18.0).color(color));
        ui.strong(text);
    });
    ui.add_space(2.0);
}

/// Name and value rows with the names in one aligned column. Values wrap
/// within the card (a grid would let them run past it).
fn rows(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    let body = ui.text_style_height(&egui::TextStyle::Body);
    let label_width = (ui.available_width() * 0.36)
        .min(body * 6.5)
        .max(body * 3.5);
    ui.push_id(id, |ui| {
        ui.spacing_mut().item_spacing.y = body * 0.45;
        for (name, value) in rows {
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(label_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(label_width);
                        ui.add(egui::Label::new(RichText::new(*name).color(theme::muted())).wrap());
                    },
                );
                ui.add(egui::Label::new(value.as_str()).wrap());
            });
        }
    });
}

/// A large figure with a unit, as the resource cards show readings.
fn figure(ui: &mut egui::Ui, value: &str, unit: &str) {
    let body = ui.text_style_height(&egui::TextStyle::Body);
    let format = |size: f32, color: Color32| egui::TextFormat {
        font_id: egui::FontId::proportional(size),
        color,
        valign: egui::Align::BOTTOM,
        ..Default::default()
    };
    let mut job = egui::text::LayoutJob::default();
    job.append(value, 0.0, format(body * 1.9, theme::heading()));
    job.append(&format!(" {unit}"), 0.0, format(body, theme::muted()));
    ui.add(egui::Label::new(job).wrap());
}

fn compute(ui: &mut egui::Ui, vm: &VmConfig) {
    title(ui, icon::CPU, "Compute", theme::blue());
    figure(ui, &vm.cpus.to_string(), "vCPU");
    let ram = if vm.ram_mib.is_multiple_of(1024) {
        format!("{} GiB", vm.ram_mib / 1024)
    } else {
        format!("{} MiB", vm.ram_mib)
    };
    rows(
        ui,
        "summary-config-compute",
        &[
            ("RAM", ram),
            ("CPU model", vm.launch.cpu_model.label().to_owned()),
            ("Acceleration", vm.launch.acceleration.label().to_owned()),
        ],
    );
}

fn storage(ui: &mut egui::Ui, vm: &VmConfig, snapshot: &Snapshot) {
    title(ui, icon::HARD_DRIVES, "Storage and display", theme::blue());
    figure(ui, &vm.disk_gib.to_string(), "GiB disk");
    let base = crate::app::selected_base(snapshot, vm.base_identity.as_deref())
        .map(|base| base.label.clone())
        .unwrap_or_else(|| {
            vm.base_identity
                .clone()
                .unwrap_or_else(|| "Default base".into())
        });
    let mut display = vm.launch.resolution.label().to_owned();
    if vm.launch.fullscreen {
        display.push_str(" · Fullscreen");
    }
    if vm.launch.fit_to_window {
        display.push_str(" · Fit to window");
    }
    rows(
        ui,
        "summary-config-storage",
        &[("Base image", base), ("Display", display)],
    );
}

fn network(ui: &mut egui::Ui, vm: &VmConfig) {
    let connected = vm.nat || vm.isolated_network;
    title(
        ui,
        icon::NETWORK,
        "Network and transport",
        if connected {
            theme::blue()
        } else {
            theme::muted()
        },
    );
    ui.label(
        RichText::new(network_label(vm))
            .size(ui.text_style_height(&egui::TextStyle::Body) * 1.15)
            .strong()
            .color(theme::heading()),
    );
    let wait = vm.transport.send_wait_us();
    rows(
        ui,
        "summary-config-network",
        &[
            ("Ring", format!("{} KiB per vCPU", vm.transport.ring_kib)),
            (
                "When full",
                if wait == 0 {
                    "Drops telemetry".to_owned()
                } else {
                    format!("Waits up to {}", wait_label(wait))
                },
            ),
        ],
    );
}

fn wait_label(microseconds: u32) -> String {
    match microseconds {
        0..1_000 => format!("{microseconds} µs"),
        1_000..1_000_000 => format!("{} ms", microseconds / 1_000),
        _ => format!("{:.0} s", f64::from(microseconds) / 1e6),
    }
}

/// A rounded tag, tinted with `color`.
fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.16))
        .stroke(egui::Stroke::new(1.0_f32, color.gamma_multiply(0.7)))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(8, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().color(color));
        });
}

fn on_off(on: bool, yes: &str, no: &str) -> String {
    if on { yes } else { no }.to_owned()
}

fn firmware_kind(firmware: Firmware) -> &'static str {
    match firmware {
        Firmware::Bios => "SeaBIOS",
        Firmware::Uefi => "UEFI",
        Firmware::UefiSecureBoot => "UEFI Secure Boot",
    }
}

fn stealth(ui: &mut egui::Ui, profile: &StealthProfile, narrow: bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(icon::SHIELD).size(18.0).color(theme::blue()));
        ui.strong("Stealth profile");
        pill(ui, profile.preset.label(), theme::blue());
    });
    ui.add_space(2.0);
    let identity = &profile.identity;
    let machine = if profile.identity_enabled {
        let name = MACHINES
            .iter()
            .find(|machine| machine.id == identity.profile)
            .map(|machine| machine.label.to_owned())
            .unwrap_or_else(|| {
                format!(
                    "{} {}",
                    identity.system_manufacturer, identity.system_product
                )
            });
        format!("{name} · {}", chassis_label(identity.chassis_type))
    } else {
        "QEMU Standard PC (Q35 + ICH9) · Other".to_owned()
    };
    let mut hardware = vec![("Machine", machine)];
    if profile.identity_enabled {
        hardware.push(("Serial", identity.system_serial.clone()));
        hardware.push((
            "Firmware",
            format!(
                "{} · {} {} ({})",
                firmware_kind(profile.firmware),
                identity.bios_vendor,
                identity.bios_version,
                identity.bios_date
            ),
        ));
        hardware.push(("ACPI OEM", identity.acpi_oem_id.trim_end().to_owned()));
    } else {
        hardware.push((
            "Firmware",
            format!("{} · ACPI OEM BOCHS", firmware_kind(profile.firmware)),
        ));
    }
    let mut cpu = vec![if profile.cpu_passthrough {
        "Host CPU"
    } else {
        "QEMU model"
    }];
    if profile.hide_hypervisor {
        cpu.push("hypervisor flag hidden");
    }
    if profile.hide_kvm {
        cpu.push("KVM hidden");
    }
    if profile.pmu {
        cpu.push("counters");
    }
    if profile.smt && profile.realistic_topology {
        cpu.push("2 threads per core");
    }
    let mut devices = vec![match profile.disk_bus {
        DiskBus::Virtio => "virtio disk",
        DiskBus::Sata => "SATA disk",
        DiskBus::Nvme => "NVMe disk",
    }];
    if profile.cdrom {
        devices.push("CD-ROM");
    }
    if profile.usb {
        devices.push("ICH9 USB");
    }
    if profile.hpet {
        devices.push("HPET");
    }
    devices.push(if profile.vmport {
        "VMware port"
    } else {
        "no VMware port"
    });
    let machine_rows = [
        ("CPU", cpu.join(" · ")),
        (
            "Network card",
            format!(
                "{} · {}",
                profile.nic.label(),
                if profile.mac.is_empty() {
                    "QEMU default MAC"
                } else {
                    profile.mac.as_str()
                }
            ),
        ),
        (
            "NAT",
            if profile.nat.network.is_empty() {
                "10.0.2.0/24 (QEMU)".to_owned()
            } else {
                format!("{} via {}", profile.nat.network, profile.nat.gateway)
            },
        ),
        ("Devices", devices.join(" · ")),
        (
            "Clock",
            on_off(profile.rtc_localtime, "RTC local time", "RTC UTC"),
        ),
    ];
    if narrow {
        rows(ui, "summary-stealth-identity", &hardware);
        rows(ui, "summary-stealth-machine", &machine_rows);
    } else {
        ui.scope(|ui| {
            ui.spacing_mut().item_spacing.x = 28.0;
            ui.columns(2, |columns| {
                rows(&mut columns[0], "summary-stealth-identity", &hardware);
                rows(&mut columns[1], "summary-stealth-machine", &machine_rows);
            });
        });
    }
    let giveaways = profile.giveaways();
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Still visible").small().color(theme::muted()));
        let shown = giveaways
            .iter()
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(" · ");
        let more = giveaways.len().saturating_sub(3);
        ui.label(RichText::new(shown).small())
            .on_hover_text(format!("• {}", giveaways.join("\n• ")));
        if more > 0 {
            ui.label(
                RichText::new(format!("and {more} more"))
                    .small()
                    .color(theme::muted()),
            )
            .on_hover_text(format!("• {}", giveaways.join("\n• ")));
        }
    });
    if profile.preset == StealthPreset::Transparent {
        ui.label(
            RichText::new(
                "QEMU's own identity. Choose a Realistic preset in Configure… to hide it.",
            )
            .small()
            .color(theme::muted()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drawn(
        vm: &VmConfig,
        snapshot: &Snapshot,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        fn collect(shape: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(text) => {
                    out.push((text.galley.text().to_owned(), text.visual_bounding_rect()))
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
                _ => {}
            }
        }
        // No theme::install: it resets the global palette that a light-theme
        // test in another module relies on while tests run in parallel.
        let ctx = egui::Context::default();
        let mut output = None;
        for frame in 0..4 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1100.0, 1400.0),
                )),
                events: if frame == 3 {
                    events.clone()
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            output = Some(ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| show(ui, vm, snapshot));
            }));
        }
        let mut texts = Vec::new();
        for shape in &output.unwrap().shapes {
            collect(&shape.shape, &mut texts);
        }
        if ctx.data_mut(|data| data.remove_temp::<bool>(egui::Id::new(CONFIGURE))) == Some(true) {
            texts.push(("<configure>".into(), egui::Rect::NOTHING));
        }
        texts
    }

    fn vm(stealth: StealthProfile) -> VmConfig {
        VmConfig {
            id: "vm".into(),
            name: "VM".into(),
            stealth,
            ..VmConfig::default()
        }
    }

    #[test]
    fn cards_show_the_configuration_and_the_stealth_profile() {
        let profile = StealthProfile::realistic(StealthPreset::RealisticDesktop, "GenuineIntel");
        let machine = MACHINES
            .iter()
            .find(|machine| machine.id == profile.identity.profile)
            .unwrap()
            .label;
        let texts: Vec<String> = drawn(&vm(profile.clone()), &Snapshot::default(), Vec::new())
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        for expected in [
            "Compute",
            "Storage and display",
            "Network and transport",
            "Stealth profile",
            "Realistic desktop",
            profile.identity.system_serial.as_str(),
        ] {
            assert!(
                texts.iter().any(|text| text == expected),
                "{expected}: {texts:?}"
            );
        }
        assert!(
            texts.iter().any(|text| text.starts_with(machine)),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|text| text.contains(&profile.mac)),
            "{texts:?}"
        );
    }

    #[test]
    fn transparent_vms_say_qemu_identity_is_visible() {
        let texts: Vec<String> = drawn(
            &vm(StealthProfile::transparent()),
            &Snapshot::default(),
            Vec::new(),
        )
        .into_iter()
        .map(|(text, _)| text)
        .collect();
        assert!(
            !texts.iter().any(|text| text.contains("Detected as a VM")),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|text| text.starts_with("QEMU's own identity")),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|text| text.contains("QEMU default MAC")),
            "{texts:?}"
        );
    }

    #[test]
    fn configure_is_offered_only_while_the_vm_is_stopped() {
        let stopped = vm(StealthProfile::transparent());
        let button = drawn(&stopped, &Snapshot::default(), Vec::new())
            .into_iter()
            .find(|(text, _)| text.ends_with("Configure…"))
            .expect("Configure… button")
            .1
            .center();
        let click = |pressed| egui::Event::PointerButton {
            pos: button,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let events = vec![egui::Event::PointerMoved(button), click(true), click(false)];
        let texts = drawn(&stopped, &Snapshot::default(), events.clone());
        assert!(texts.iter().any(|(text, _)| text == "<configure>"));
        let running = Snapshot {
            active_vm: Some("vm".into()),
            ..Snapshot::default()
        };
        let texts = drawn(&stopped, &running, events);
        assert!(!texts.iter().any(|(text, _)| text == "<configure>"));
    }

    #[test]
    fn waits_read_in_the_largest_whole_unit() {
        assert_eq!(wait_label(250), "250 µs");
        assert_eq!(wait_label(20_000), "20 ms");
        assert_eq!(wait_label(5_000_000), "5 s");
    }
}
