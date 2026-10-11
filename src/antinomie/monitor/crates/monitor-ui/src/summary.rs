// SPDX-License-Identifier: MIT
//! Selected-VM overview; live values are always scoped to the active VM.
use crate::theme;
use antinomie_monitor_core::{Snapshot, VmConfig, VmState};
use eframe::egui::{self, RichText};

pub(crate) fn show(ui: &mut egui::Ui, snapshot: &Snapshot, selected: Option<&str>) {
    egui::ScrollArea::vertical()
        .id_salt("vm-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.heading("VM status");
            let Some(vm) = selected.and_then(|id| snapshot.vms.iter().find(|vm| vm.id == id)) else {
                ui.label("Select a VM from the sidebar to see its status and configuration.");
                if snapshot.vms.is_empty() {
                    ui.label("Create a VM from File → New VM, or add a base first.");
                }
                return;
            };
            let active = snapshot.active_vm.as_deref() == Some(vm.id.as_str());
            ui.label(RichText::new(&vm.name).strong());
            row(ui, "State", state_label(snapshot, active));
            let base = crate::app::selected_base(snapshot, vm.base_identity.as_deref());
            row(ui, "Base", base.map_or("Unavailable", |base| base.label.as_str()));
            if let Some(revision) = base.and_then(|base| base.revision) {
                row(ui, "Guest revision", revision.to_string());
            }
            row(ui, "Network", network_label(vm));
            row(ui, "Configured CPUs", format!("{} vCPU", vm.cpus));
            row(ui, "Configured RAM", format!("{} MiB", vm.ram_mib));
            row(ui, "Configured disk", format!("{} GiB", vm.disk_gib));
            if active {
                if let Some(error) = &snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
            }

            section(ui, "Health");
            if active {
                health(ui, snapshot);
            } else {
                ui.label("Live health is available while this VM is active.");
                if snapshot.active_vm.is_some() {
                    ui.label("Another VM is active; its health is shown in its own Summary.");
                }
            }

            section(ui, "Resources");
            if !active {
                ui.label("Start this VM to measure QEMU CPU and resident memory.");
                return;
            }
            let Some(resources) = snapshot.vm_resources.as_ref().filter(|resources| {
                resources.vm_id == vm.id
            }) else {
                ui.label("Waiting for the first resource sample.");
                return;
            };
            let uptime = resources.uptime_ms.map_or_else(|| "Unavailable".into(), uptime);
            row(ui, "VM uptime", uptime);
            ui.add(egui::Label::new(RichText::new(
                "Uptime is elapsed host time since QEMU started, including pauses.",
            ).color(theme::muted())).wrap());
            row(
                ui,
                "QEMU CPU",
                resources.qemu_cpu_percent.map_or_else(
                    || "Unavailable".into(),
                    |percent| format!("{percent:.1}% (100% = one host CPU core)"),
                ),
            );
            row(ui, "QEMU resident memory", optional_size(resources.qemu_resident_size));
            row(ui, "Host data-volume free", optional_size(resources.data_disk_available_size));
            ui.add(egui::Label::new(RichText::new(
                "Resident memory includes QEMU overhead. Configured RAM is capacity; guest RAM utilization is unavailable.",
            ).color(theme::muted())).wrap());
            if let Some(error) = &resources.sample_error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
        });
}

fn state_label(snapshot: &Snapshot, active: bool) -> &'static str {
    if !active {
        return "Stopped";
    }
    match snapshot.state {
        VmState::Stopped => "Stopped",
        VmState::Starting => "Starting",
        VmState::Running => "Running",
        VmState::Stopping => "Stopping",
        VmState::Failed => "Failed",
    }
}

fn network_label(vm: &VmConfig) -> &'static str {
    if vm.isolated_network {
        "Isolated"
    } else if vm.nat {
        "NAT / external access"
    } else {
        "Disabled"
    }
}

fn health(ui: &mut egui::Ui, snapshot: &Snapshot) {
    let health = &snapshot.health;
    let impaired = health.dropped > 0
        || health.storage_dropped_packets > 0
        || health.parser_errors > 0
        || health.parser_evicted_count > 0
        || health.ui_dropped > 0
        || health.bad_commands > 0
        || health.reply_stalls > 0
        || health.transport_health != 0
        || health.persistence_error.is_some()
        || health.shedding;
    let (label, color) = if health.persistence_error.is_some() {
        ("Recording error", theme::error())
    } else if impaired {
        ("Loss or errors recorded", theme::warn())
    } else {
        ("No loss or errors reported", theme::text())
    };
    ui.colored_label(color, label);
    ui.add(egui::Label::new(RichText::new(
        "Counters describe this VM session and capture completeness; they do not assess malware risk.",
    ).color(theme::muted())).wrap());
    row(ui, "Guest sends attempted", health.attempted.to_string());
    row(ui, "Guest transport drops", health.dropped.to_string());
    row(
        ui,
        "Host packets received",
        health.received_packets.to_string(),
    );
    row(
        ui,
        "Storage packet drops",
        health.storage_dropped_packets.to_string(),
    );
    row(
        ui,
        "Parser errors / evictions",
        format!("{} / {}", health.parser_errors, health.parser_evicted_count),
    );
    row(ui, "UI preview drops", health.ui_dropped.to_string());
    row(
        ui,
        "Bad commands / reply stalls",
        format!("{} / {}", health.bad_commands, health.reply_stalls),
    );
    row(
        ui,
        "Transport status flags",
        format!("0x{:08x}", health.transport_health),
    );
    row(
        ui,
        "Capture All shedding",
        if health.shedding {
            "Active — telemetry is being dropped"
        } else {
            "Inactive"
        },
    );
    row(
        ui,
        "Packets persisted",
        health.persisted_packets.to_string(),
    );
    row(ui, "Recording written", size(health.persisted_len));
    row(ui, "Recording write backlog", size(health.write_backlog));
    row(
        ui,
        "Transport waits",
        format!(
            "{} ({:.3} s total)",
            health.transport_waits,
            health.transport_wait_ns as f64 / 1_000_000_000.0
        ),
    );
    if let Some(error) = &health.persistence_error {
        ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
    }
}

fn section(ui: &mut egui::Ui, label: &str) {
    ui.add_space(8.0);
    ui.separator();
    ui.label(RichText::new(label).strong().color(theme::heading()));
}

/// Rows wrap the value onto the next line instead of clipping at large font sizes.
fn row(ui: &mut egui::Ui, label: &str, value: impl AsRef<str>) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}:")).color(theme::muted()));
        ui.add(egui::Label::new(value.as_ref()).wrap());
    });
}

fn optional_size(value: Option<u64>) -> String {
    value.map_or_else(|| "Unavailable".into(), size)
}

fn size(value: u64) -> String {
    format!("{:.1} MiB", value as f64 / 1_048_576.0)
}

fn uptime(milliseconds: u64) -> String {
    let seconds = milliseconds / 1000;
    format!(
        "{} h {:02} m {:02} s",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::VmResources;

    fn fixture() -> Snapshot {
        Snapshot {
            vms: vec![
                VmConfig {
                    id: "active".into(),
                    name: "Active analysis VM".into(),
                    ..VmConfig::default()
                },
                VmConfig {
                    id: "stopped".into(),
                    name: "Stopped comparison VM".into(),
                    isolated_network: true,
                    ..VmConfig::default()
                },
            ],
            active_vm: Some("active".into()),
            state: VmState::Running,
            vm_resources: Some(VmResources {
                vm_id: "active".into(),
                uptime_ms: Some(3_661_000),
                qemu_cpu_percent: Some(123.4),
                qemu_resident_size: Some(1_048_576),
                data_disk_available_size: Some(12_345_678),
                sample_error: Some("Resource sample warning".into()),
            }),
            ..Snapshot::default()
        }
    }

    fn render(
        snapshot: &Snapshot,
        selected: Option<&str>,
        width: f32,
        font: f32,
    ) -> Vec<(String, egui::Rect)> {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font);
        let size = egui::vec2(width, 2800.0);
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| show(ui, snapshot, selected));
                },
            );
        }
        output
            .shapes
            .iter()
            .filter_map(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    Some((
                        text.galley.job.text.clone(),
                        text.galley.rect.translate(text.pos.to_vec2()),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn stopped_selection_does_not_show_another_vms_health_or_resources() {
        let mut snapshot = fixture();
        snapshot.health.persistence_error = Some("Other VM recording failure".into());
        let texts = render(&snapshot, Some("stopped"), 520.0, 24.0);
        let text: String = texts.iter().map(|(text, _)| text.as_str()).collect();
        assert!(text.contains("Stopped") && text.contains("Isolated"));
        assert!(!text.contains("Other VM recording failure"));
        assert!(!text.contains("123.4%"));
        assert!(!text.contains("Resource sample warning"));
    }

    #[test]
    fn no_vm_selection_guides_setup_without_showing_stale_live_data() {
        let text: String = render(&Snapshot::default(), None, 520.0, 24.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(text.contains("Select a VM"));
        assert!(text.contains("Create a VM"));
        let text: String = render(&fixture(), None, 520.0, 24.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(!text.contains("123.4%"));
    }

    #[test]
    fn active_selection_surfaces_loss_storage_failure_and_resource_units() {
        let mut snapshot = fixture();
        snapshot.health.dropped = 7;
        snapshot.health.storage_dropped_packets = 8;
        snapshot.health.persistence_error = Some("Disk full while recording".into());
        snapshot.health.shedding = true;
        let text: String = render(&snapshot, Some("active"), 900.0, 18.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(text.contains("Recording error"));
        assert!(text.contains("Disk full while recording"));
        assert!(text.contains("Active — telemetry is being dropped"));
        assert!(text.contains("123.4% (100% = one host CPU core)"));
        assert!(text.contains("1 h 01 m 01 s"));
        assert!(text.contains("guest RAM utilization is unavailable"));
    }

    #[test]
    fn resource_identity_mismatch_and_warming_cpu_are_explicit() {
        let mut snapshot = fixture();
        snapshot.vm_resources.as_mut().unwrap().vm_id = "stopped".into();
        let text: String = render(&snapshot, Some("active"), 600.0, 18.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(text.contains("Waiting for the first resource sample"));
        assert!(!text.contains("123.4%"));
        snapshot.vm_resources.as_mut().unwrap().vm_id = "active".into();
        snapshot.vm_resources.as_mut().unwrap().qemu_cpu_percent = None;
        let text: String = render(&snapshot, Some("active"), 600.0, 18.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(text.contains("QEMU CPU:") && text.contains("Unavailable"));
        assert!(!text.contains("0.0%"));
    }

    #[test]
    fn summary_wraps_values_at_large_font_and_narrow_width() {
        let mut snapshot = fixture();
        snapshot.health.persistence_error = Some("An example recording error with enough words to wrap across several lines at a narrow operational panel width.".into());
        for width in [320.0, 520.0, 900.0] {
            let texts = render(&snapshot, Some("active"), width, 24.0);
            assert!(texts.iter().any(|(text, _)| text == "Resources"));
            for (text, rect) in texts {
                assert!(
                    rect.right() <= width + 1.0,
                    "{text:?} extends beyond {width}: {rect:?}"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires X11 native rendering; exits after 20 seconds"]
    fn native_summary_fixture() {
        use std::time::{Duration, Instant};
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct Fixture {
            snapshot: Snapshot,
            deadline: Instant,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                egui::CentralPanel::default()
                    .show(ctx, |ui| show(ui, &self.snapshot, Some("active")));
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        eframe::run_native(
            "Antinomie Summary QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size([520.0, 720.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(|cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, 24.0);
                let mut snapshot = fixture();
                snapshot.health.dropped = 7;
                snapshot.health.shedding = true;
                Ok(Box::new(Fixture {
                    snapshot,
                    deadline: Instant::now() + Duration::from_secs(20),
                }))
            }),
        )
        .unwrap();
    }
}
