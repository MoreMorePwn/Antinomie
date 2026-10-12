// SPDX-License-Identifier: MIT
//! Selected-VM overview; live values are always scoped to the active VM.
use crate::theme;
use antinomie_monitor_core::{Snapshot, VmConfig, VmResources, VmState};
use eframe::egui::{self, RichText};
use std::collections::VecDeque;

const HISTORY_LIMIT: usize = 60;

#[derive(Clone, Default)]
struct CpuHistory {
    identity: Option<(String, Option<String>)>,
    sequence: Option<u64>,
    uptime_ms: Option<u64>,
    samples: VecDeque<Option<f64>>,
}

impl CpuHistory {
    fn observe(&mut self, snapshot: &Snapshot, selected: Option<&str>) {
        let Some(resources) = selected
            .filter(|id| snapshot.active_vm.as_deref() == Some(*id))
            .and_then(|id| {
                snapshot
                    .vm_resources
                    .as_ref()
                    .filter(|sample| sample.vm_id == id)
            })
        else {
            *self = Self::default();
            return;
        };
        let identity = (resources.vm_id.clone(), snapshot.boot_id.clone());
        let restarted = self
            .sequence
            .is_some_and(|sequence| resources.sample_sequence < sequence)
            || self
                .uptime_ms
                .zip(resources.uptime_ms)
                .is_some_and(|(old, new)| new < old);
        if self.identity.as_ref() != Some(&identity) || restarted {
            *self = Self {
                identity: Some(identity),
                ..Self::default()
            };
        }
        if self.sequence == Some(resources.sample_sequence) {
            return;
        }
        if let Some(previous) = self.sequence {
            let gaps = resources
                .sample_sequence
                .saturating_sub(previous)
                .saturating_sub(1)
                .min(HISTORY_LIMIT as u64);
            for _ in 0..gaps {
                self.push(None);
            }
        }
        self.push(cpu_value(resources.qemu_cpu_percent));
        self.sequence = Some(resources.sample_sequence);
        if resources.uptime_ms.is_some() {
            self.uptime_ms = resources.uptime_ms;
        }
    }

    fn push(&mut self, value: Option<f64>) {
        if self.samples.len() == HISTORY_LIMIT {
            self.samples.pop_front();
        }
        self.samples.push_back(value);
    }

    fn scale(&self, cpus: u16) -> f64 {
        let maximum = self
            .samples
            .iter()
            .flatten()
            .copied()
            .fold(f64::from(cpus.max(1)) * 100.0, f64::max);
        let rounded = (maximum / 100.0).ceil() * 100.0;
        if rounded.is_finite() {
            rounded
        } else {
            maximum
        }
    }
}

fn cpu_value(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value >= 0.0)
}

pub(crate) fn show(ui: &mut egui::Ui, snapshot: &Snapshot, selected: Option<&str>) {
    let history = ui.ctx().data_mut(|data| {
        let history =
            data.get_temp_mut_or_default::<CpuHistory>(egui::Id::new("summary-cpu-history"));
        history.observe(snapshot, selected);
        history.clone()
    });
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
            indicator(ui, state_label(snapshot, active), state_color(snapshot, active));
            let base = crate::app::selected_base(snapshot, vm.base_identity.as_deref());
            row(ui, "Base", base.map_or("Unavailable", |base| base.label.as_str()));
            if let Some(revision) = base.and_then(|base| base.revision) {
                row(ui, "Guest revision", revision.to_string());
            }
            row(ui, "Network", network_label(vm));
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{} vCPU configured", vm.cpus));
                ui.label(format!("RAM capacity: {} MiB", vm.ram_mib));
                ui.label(format!("Disk capacity: {} GiB", vm.disk_gib));
            });
            if active {
                if let Some(error) = &snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
            }

            section(ui, "Health");
            if active {
                let (label, color) = health_state(snapshot);
                indicator(ui, label, color);
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Transport drops: {}", snapshot.health.dropped));
                    ui.label(format!("Storage drops: {}", snapshot.health.storage_dropped_packets));
                    ui.label(format!("UI preview drops: {}", snapshot.health.ui_dropped));
                });
                if snapshot.health.shedding {
                    ui.add(egui::Label::new(RichText::new("Active — telemetry is being dropped by Capture All shedding").color(theme::warn())).wrap());
                }
                if let Some(error) = &snapshot.health.persistence_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
                egui::CollapsingHeader::new("Health counters")
                    .id_salt("summary-health-counters")
                    .show(ui, |ui| health(ui, snapshot));
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
            cpu_chart(ui, &history, resources, vm.cpus);
            ui.add_space(8.0);
            let minimum = ui.text_style_height(&egui::TextStyle::Body) * 15.0;
            if ui.available_width() >= minimum * 2.0 + ui.spacing().item_spacing.x {
                ui.columns(2, |columns| {
                    memory_meter(&mut columns[0], resources);
                    disk_meter(&mut columns[1], resources);
                });
            } else {
                memory_meter(ui, resources);
                ui.add_space(8.0);
                disk_meter(ui, resources);
            }
            row(ui, "VM uptime", resources.uptime_ms.map_or_else(|| "Unavailable".into(), uptime));
            ui.add(egui::Label::new(RichText::new("Uptime includes host time while QEMU is paused.").color(theme::muted())).wrap());
            ui.add(egui::Label::new(RichText::new(
                "Resident memory includes QEMU overhead. Configured RAM is capacity; guest RAM utilization is unavailable.",
            ).color(theme::muted())).wrap());
            if let Some(error) = &resources.sample_error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
        });
}

fn indicator(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    ui.horizontal_wrapped(|ui| {
        let height = ui.text_style_height(&egui::TextStyle::Body);
        let (rect, _) =
            ui.allocate_exact_size(egui::vec2(height * 0.65, height), egui::Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), height * 0.17, color);
        ui.colored_label(color, label);
    });
}

fn state_color(snapshot: &Snapshot, active: bool) -> egui::Color32 {
    if !active {
        return theme::muted();
    }
    match snapshot.state {
        VmState::Running => theme::good(),
        VmState::Starting | VmState::Stopping => theme::warn(),
        VmState::Failed => theme::error(),
        VmState::Stopped => theme::muted(),
    }
}

fn cpu_chart(ui: &mut egui::Ui, history: &CpuHistory, resources: &VmResources, cpus: u16) {
    row(
        ui,
        "QEMU CPU",
        cpu_value(resources.qemu_cpu_percent).map_or_else(
            || "Unavailable".into(),
            |value| format!("{value:.1}% (100% = one host CPU core)"),
        ),
    );
    let scale = history.scale(cpus);
    ui.add(egui::Label::new(RichText::new(format!("Recent 60 samples · Scale 0–{scale:.0}%")).color(theme::muted())).wrap())
        .on_hover_text("Samples are retained while Summary is visible. Missing observations break the line; they are not zero CPU usage. The graph starts at the configured vCPU scale and expands for QEMU overhead.");
    let height = (ui.text_style_height(&egui::TextStyle::Body) * 4.0).max(96.0);
    let (response, painter) = ui.allocate_painter(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let rect = response.rect.shrink(1.0);
    painter.rect_filled(rect, 3.0, theme::bg());
    painter.rect_stroke(
        rect,
        3.0,
        egui::Stroke::new(1.0_f32, theme::line()),
        egui::StrokeKind::Inside,
    );
    for step in 1..4 {
        let y = rect.bottom() - rect.height() * step as f32 / 4.0;
        painter.line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            egui::Stroke::new(0.5_f32, theme::line()),
        );
    }
    let mut previous: Option<egui::Pos2> = None;
    let start = HISTORY_LIMIT - history.samples.len();
    for (index, value) in history.samples.iter().enumerate() {
        let Some(value) = value else {
            previous = None;
            continue;
        };
        let point = egui::pos2(
            rect.left() + rect.width() * (start + index) as f32 / (HISTORY_LIMIT - 1) as f32,
            rect.bottom() - rect.height() * (value / scale).clamp(0.0, 1.0) as f32,
        );
        if let Some(before) = previous {
            let color = theme::blue();
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(before.x, rect.bottom()),
                    before,
                    point,
                    egui::pos2(point.x, rect.bottom()),
                ],
                egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 35),
                egui::Stroke::NONE,
            ));
            painter.line_segment([before, point], egui::Stroke::new(1.8_f32, color));
        } else {
            painter.circle_filled(point, 2.0, theme::blue());
        }
        previous = Some(point);
    }
}

fn fraction(value: Option<u64>, total: Option<u64>) -> Option<f64> {
    value
        .zip(total.filter(|total| *total > 0))
        .map(|(value, total)| value as f64 / total as f64)
}

fn meter(ui: &mut egui::Ui, fraction: Option<f64>, color: egui::Color32, unavailable: &str) {
    let height = (ui.text_style_height(&egui::TextStyle::Body) * 0.6).max(10.0);
    let (response, painter) = ui.allocate_painter(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let rect = response.rect;
    painter.rect_filled(rect, 3.0, theme::raised());
    if let Some(fraction) = fraction.filter(|fraction| fraction.is_finite()) {
        let filled = egui::Rect::from_min_size(
            rect.min,
            egui::vec2(
                rect.width() * fraction.clamp(0.0, 1.0) as f32,
                rect.height(),
            ),
        );
        if filled.width() > 0.0 {
            painter.rect_filled(filled, 3.0, color);
        }
    } else {
        painter.rect_stroke(
            rect,
            3.0,
            egui::Stroke::new(1.0_f32, theme::line()),
            egui::StrokeKind::Inside,
        );
        ui.colored_label(theme::muted(), unavailable);
    }
}

fn memory_meter(ui: &mut egui::Ui, resources: &VmResources) {
    ui.label(RichText::new("QEMU resident memory").strong());
    row(ui, "Resident", optional_size(resources.qemu_resident_size));
    row(
        ui,
        "Host-visible RAM",
        optional_size(resources.host_memory_total_size),
    );
    let ratio = fraction(
        resources.qemu_resident_size,
        resources.host_memory_total_size,
    );
    if let Some(ratio) = ratio {
        row(
            ui,
            "QEMU share",
            format!("{:.1}% of host-visible RAM", ratio * 100.0),
        );
    }
    meter(
        ui,
        ratio,
        theme::blue(),
        if resources
            .host_memory_total_size
            .is_none_or(|total| total == 0)
        {
            "Capacity unavailable"
        } else {
            "Resident measurement unavailable"
        },
    );
}

fn disk_meter(ui: &mut egui::Ui, resources: &VmResources) {
    ui.label(RichText::new("Host data-volume").strong());
    row(
        ui,
        "Available to app",
        optional_size(resources.data_disk_available_size),
    );
    row(
        ui,
        "Volume capacity",
        optional_size(resources.data_disk_total_size),
    );
    let ratio = resources
        .data_disk_available_size
        .zip(resources.data_disk_total_size)
        .filter(|(available, total)| available <= total)
        .and_then(|(available, total)| fraction(Some(available), Some(total)));
    if let Some(ratio) = ratio {
        row(ui, "Available share", format!("{:.1}%", ratio * 100.0));
    }
    if let Some(unavailable) = resources
        .data_disk_total_size
        .zip(resources.data_disk_available_size)
        .and_then(|(total, available)| total.checked_sub(available))
    {
        row(ui, "Unavailable to app", size(unavailable));
    }
    meter(
        ui,
        ratio,
        theme::good(),
        if resources
            .data_disk_total_size
            .is_none_or(|total| total == 0)
        {
            "Capacity unavailable"
        } else if resources.data_disk_available_size.is_none() {
            "Available-space measurement unavailable"
        } else {
            "Inconsistent volume measurement"
        },
    );
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

fn health_state(snapshot: &Snapshot) -> (&'static str, egui::Color32) {
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
    if health.persistence_error.is_some() {
        ("Recording error", theme::error())
    } else if impaired {
        ("Loss or errors recorded", theme::warn())
    } else {
        ("No loss or errors reported", theme::good())
    }
}

fn health(ui: &mut egui::Ui, snapshot: &Snapshot) {
    let health = &snapshot.health;
    let (label, color) = health_state(snapshot);
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
    if value >= 1_073_741_824 {
        format!("{:.1} GiB", value as f64 / 1_073_741_824.0)
    } else {
        format!("{:.1} MiB", value as f64 / 1_048_576.0)
    }
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
                sample_sequence: 1,
                uptime_ms: Some(3_661_000),
                qemu_cpu_percent: Some(123.4),
                qemu_resident_size: Some(1_048_576),
                host_memory_total_size: Some(16 * 1_073_741_824),
                data_disk_available_size: Some(12_345_678),
                data_disk_total_size: Some(512 * 1_073_741_824),
                sample_error: Some("Resource sample warning".into()),
            }),
            ..Snapshot::default()
        }
    }

    #[test]
    fn history_deduplicates_frames_and_preserves_missing_or_unknown_samples() {
        let mut snapshot = fixture();
        let mut history = CpuHistory::default();
        for _ in 0..5 {
            history.observe(&snapshot, Some("active"));
        }
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 4;
        snapshot.vm_resources.as_mut().unwrap().qemu_cpu_percent = None;
        history.observe(&snapshot, Some("active"));
        assert_eq!(
            history.samples.iter().copied().collect::<Vec<_>>(),
            [Some(123.4), None, None, None]
        );
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 5;
        snapshot.vm_resources.as_mut().unwrap().qemu_cpu_percent = Some(0.0);
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.back(), Some(&Some(0.0)));
    }

    #[test]
    fn history_is_bounded_and_resets_at_selection_boot_sequence_and_uptime_boundaries() {
        let mut snapshot = fixture();
        let mut history = CpuHistory::default();
        for sequence in 1..=120 {
            snapshot.vm_resources.as_mut().unwrap().sample_sequence = sequence;
            history.observe(&snapshot, Some("active"));
        }
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        history.observe(&snapshot, Some("stopped"));
        assert!(history.samples.is_empty());
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.boot_id = Some("new-boot".into());
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 121;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 2);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 1;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 2;
        history.observe(&snapshot, Some("active"));
        snapshot.vm_resources.as_mut().unwrap().uptime_ms = Some(1);
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().vm_id = "wrong-vm".into();
        history.observe(&snapshot, Some("active"));
        assert!(history.samples.is_empty());
    }

    #[test]
    fn history_large_sequence_gaps_are_bounded_and_cpu_scale_keeps_one_core_units() {
        let mut snapshot = fixture();
        let mut history = CpuHistory::default();
        history.observe(&snapshot, Some("active"));
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = u64::MAX;
        snapshot.vm_resources.as_mut().unwrap().qemu_cpu_percent = Some(1_235.0);
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        assert_eq!(
            history
                .samples
                .iter()
                .filter(|value| value.is_some())
                .count(),
            1
        );
        assert_eq!(history.scale(4), 1_300.0);
        assert_eq!(cpu_value(Some(f64::NAN)), None);
        assert_eq!(cpu_value(Some(f64::INFINITY)), None);
        assert_eq!(cpu_value(Some(-1.0)), None);
        assert_eq!(fraction(Some(1), Some(0)), None);
        assert_eq!(fraction(Some(1), None), None);
        assert_eq!(fraction(Some(1), Some(4)), Some(0.25));
    }

    #[test]
    fn unavailable_denominators_keep_actual_values_and_do_not_invent_guest_percentages() {
        let mut snapshot = fixture();
        snapshot
            .vm_resources
            .as_mut()
            .unwrap()
            .host_memory_total_size = None;
        snapshot.vm_resources.as_mut().unwrap().data_disk_total_size = None;
        let text: String = render(&snapshot, Some("active"), 520.0, 24.0)
            .iter()
            .map(|(text, _)| text.as_str())
            .collect();
        assert!(text.contains("1.0 MiB"));
        assert!(text.contains("11.8 MiB"));
        assert!(text.contains("Capacity unavailable"));
        assert!(!text.contains("QEMU share:"));
        assert!(!text.contains("Available share:"));
        assert!(text.contains("guest RAM utilization is unavailable"));
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
        assert!(!text.contains("0.0% (100% = one host CPU core)"));
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
        let wide = std::env::var_os("ANTINOMIE_SUMMARY_QA_WIDE").is_some();
        eframe::run_native(
            "Antinomie Summary QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(if wide {
                    [1080.0, 820.0]
                } else {
                    [520.0, 720.0]
                }),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, if wide { 18.0 } else { 24.0 });
                let mut snapshot = fixture();
                snapshot.vms[0].name = "Synthetic Summary resource fixture".into();
                snapshot.health.dropped = 7;
                snapshot.health.shedding = true;
                let mut history = CpuHistory::default();
                for sequence in 1..=HISTORY_LIMIT as u64 {
                    let resources = snapshot.vm_resources.as_mut().unwrap();
                    resources.sample_sequence = sequence;
                    resources.qemu_resident_size = Some(6 * 1_073_741_824);
                    resources.data_disk_available_size = Some(128 * 1_073_741_824);
                    resources.qemu_cpu_percent = if (22..=24).contains(&sequence) {
                        None
                    } else if sequence == HISTORY_LIMIT as u64 {
                        Some(123.4)
                    } else {
                        Some(180.0 + (sequence as f64 * 0.25).sin() * 100.0)
                    };
                    history.observe(&snapshot, Some("active"));
                }
                cc.egui_ctx.data_mut(|data| {
                    data.insert_temp(egui::Id::new("summary-cpu-history"), history)
                });
                Ok(Box::new(Fixture {
                    snapshot,
                    deadline: Instant::now() + Duration::from_secs(20),
                }))
            }),
        )
        .unwrap();
    }
}
