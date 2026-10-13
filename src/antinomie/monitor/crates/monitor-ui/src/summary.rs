// SPDX-License-Identifier: MIT
//! Selected-VM overview; live values are always scoped to the active VM.
use crate::theme;
use antinomie_monitor_core::{Snapshot, VmConfig, VmResources, VmState};
use eframe::egui::{self, RichText};
use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const HISTORY_LIMIT: usize = 60;

#[derive(Clone)]
struct RetainedSample {
    cpu: Option<f64>,
    rss: Option<u64>,
    host_ram: Option<u64>,
    disk_free: Option<u64>,
    disk_total: Option<u64>,
    uptime_ms: Option<u64>,
    error: Option<String>,
    seen: Instant,
}

#[derive(Clone, Default)]
pub(crate) struct CpuHistory {
    identity: Option<(String, Option<String>)>,
    sequence: Option<u64>,
    uptime_ms: Option<u64>,
    samples: VecDeque<Option<f64>>,
    times: VecDeque<Option<Instant>>,
    retained: Option<RetainedSample>,
    stopped_at: Option<SystemTime>,
}

impl CpuHistory {
    pub(crate) fn observe(&mut self, snapshot: &Snapshot, selected: Option<&str>) {
        let Some(selected) = selected else {
            *self = Self::default();
            return;
        };
        let active = snapshot.active_vm.as_deref() == Some(selected);
        let sample = snapshot
            .vm_resources
            .as_ref()
            .filter(|sample| sample.vm_id == selected);
        if !active {
            if self.identity.as_ref().is_some_and(|(id, _)| id == selected) {
                if self.stopped_at.is_none() {
                    self.stopped_at = Some(SystemTime::now());
                }
                return;
            }
            *self = Self::default();
            return;
        }
        let Some(resources) = sample else {
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
            self.stopped_at = None;
            return;
        }
        self.stopped_at = None;
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
        self.retained = Some(RetainedSample {
            cpu: cpu_value(resources.qemu_cpu_percent),
            rss: resources.qemu_resident_size,
            host_ram: resources.host_memory_total_size,
            disk_free: resources.data_disk_available_size,
            disk_total: resources.data_disk_total_size,
            uptime_ms: resources.uptime_ms,
            error: resources.sample_error.clone(),
            seen: Instant::now(),
        });
        self.sequence = Some(resources.sample_sequence);
        if resources.uptime_ms.is_some() {
            self.uptime_ms = resources.uptime_ms;
        }
    }

    fn push(&mut self, value: Option<f64>) {
        if self.samples.len() == HISTORY_LIMIT {
            self.samples.pop_front();
            self.times.pop_front();
        }
        self.times.push_back(value.map(|_| Instant::now()));
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

pub(crate) fn show(
    ui: &mut egui::Ui,
    snapshot: &Snapshot,
    selected: Option<&str>,
    quota_gib: u32,
    history: &CpuHistory,
) {
    let bound = ui.available_width();
    egui::ScrollArea::vertical()
        .id_salt("vm-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_max_width(bound);
            let Some(vm) = selected.and_then(|id| snapshot.vms.iter().find(|vm| vm.id == id))
            else {
                ui.label("Select a VM from the sidebar to see its status and configuration.");
                if snapshot.vms.is_empty() {
                    ui.label("Create a VM from File → New VM, or add a base first.");
                }
                return;
            };
            let active = snapshot.active_vm.as_deref() == Some(vm.id.as_str());
            let base = crate::app::selected_base(snapshot, vm.base_identity.as_deref());
            let identity = |ui: &mut egui::Ui| {
                ui.label(RichText::new(&vm.name).strong());
                indicator(
                    ui,
                    state_label(snapshot, active),
                    state_color(snapshot, active),
                );
                ui.add(
                    egui::Label::new(base.map_or("Unavailable", |base| base.label.as_str())).wrap(),
                );
                if let Some(revision) = base.and_then(|base| base.revision) {
                    ui.label(format!("rev {revision}"));
                }
                ui.label(network_label(vm));
                ui.label(format!("{} vCPU", vm.cpus));
            };
            if bound < 720.0 {
                ui.vertical(|ui| identity(ui));
            } else {
                ui.horizontal_wrapped(|ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    ui.spacing_mut().item_spacing.x = 12.0;
                    identity(ui);
                });
            }
            if active {
                if let Some(error) = &snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
            }

            section(ui, "Resources");
            let live = active
                .then_some(snapshot.vm_resources.as_ref())
                .flatten()
                .filter(|resources| resources.vm_id == vm.id);
            if let Some(resources) = live {
                resource_cards(ui, resources, vm, quota_gib, None);
                cpu_chart(ui, &history, Some(resources), None, vm.cpus);
            } else if !active
                && history
                    .identity
                    .as_ref()
                    .is_some_and(|(id, _)| id == &vm.id)
            {
                if let Some(retained) = &history.retained {
                    ui.label(match history.stopped_at {
                        Some(stopped) => format!(
                            "Stopped {} · last observation {}",
                            format_utc(stopped),
                            age(retained.seen)
                        ),
                        None => format!("Last observation {}", age(retained.seen)),
                    });
                    resource_cards(
                        ui,
                        &retained_resources(retained, &vm.id),
                        vm,
                        quota_gib,
                        Some(retained),
                    );
                    cpu_chart(ui, &history, None, Some(retained), vm.cpus);
                }
            } else if active {
                ui.label("Waiting for the first resource sample.");
            } else {
                ui.label("No retained resource sample for this VM.");
            }

            section(ui, "Health");
            if active {
                let (label, color) = health_state(snapshot);
                indicator(ui, label, color);
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Transport drops: {}", snapshot.health.dropped));
                    ui.label(format!(
                        "Storage drops: {}",
                        snapshot.health.storage_dropped_packets
                    ));
                    ui.label(format!("UI preview drops: {}", snapshot.health.ui_dropped));
                });
                if snapshot.health.shedding {
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Active — telemetry is being dropped by Capture All shedding",
                            )
                            .color(theme::warn()),
                        )
                        .wrap(),
                    );
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

fn cpu_load_color(percent: f64, cpus: u16) -> egui::Color32 {
    let capacity = f64::from(cpus.max(1)) * 100.0;
    let fraction = percent / capacity;
    if fraction >= 1.0 {
        theme::error()
    } else if fraction >= 0.8 {
        theme::warn()
    } else {
        theme::blue()
    }
}

fn age(seen: Instant) -> String {
    let seconds = seen.elapsed().as_secs();
    if seconds < 60 {
        format!("{seconds} s ago")
    } else {
        format!("{} m ago", seconds / 60)
    }
}

fn format_utc(time: SystemTime) -> String {
    let Ok(duration) = time.duration_since(UNIX_EPOCH) else {
        return "Unavailable".into();
    };
    let secs = duration.as_secs();
    let day_seconds = secs % 86_400;
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        day_seconds / 3600,
        day_seconds / 60 % 60,
        day_seconds % 60
    )
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u32, day as u32)
}

fn retained_resources(sample: &RetainedSample, vm_id: &str) -> VmResources {
    VmResources {
        vm_id: vm_id.to_owned(),
        sample_sequence: 0,
        uptime_ms: sample.uptime_ms,
        qemu_cpu_percent: sample.cpu,
        qemu_resident_size: sample.rss,
        host_memory_total_size: sample.host_ram,
        data_disk_available_size: sample.disk_free,
        data_disk_total_size: sample.disk_total,
        sample_error: sample.error.clone(),
    }
}

fn resource_cards(
    ui: &mut egui::Ui,
    resources: &VmResources,
    vm: &VmConfig,
    quota_gib: u32,
    _retained: Option<&RetainedSample>,
) {
    let width = ui.available_width();
    let columns: usize = if width >= 980.0 {
        3
    } else if width >= 640.0 {
        2
    } else {
        1
    };
    let gap = 10.0;
    let card_width =
        ((width - gap * (columns.saturating_sub(1) as f32)) / columns as f32).max(140.0);
    let mut index = 0usize;
    egui::Grid::new("summary-resource-cards")
        .num_columns(columns)
        .spacing(egui::vec2(gap, gap))
        .show(ui, |ui| {
            place(ui, columns, &mut index, card_width, |ui| {
                ui.label(RichText::new("QEMU host CPU").strong());
                row(
                    ui,
                    "QEMU CPU",
                    cpu_value(resources.qemu_cpu_percent).map_or_else(
                        || "Unavailable".into(),
                        |value| format!("{value:.1}% (100% = one host CPU core)"),
                    ),
                );
                let fraction = cpu_value(resources.qemu_cpu_percent)
                    .map(|value| value / (f64::from(vm.cpus.max(1)) * 100.0));
                let color = cpu_value(resources.qemu_cpu_percent)
                    .map(|value| cpu_load_color(value, vm.cpus))
                    .unwrap_or_else(theme::muted);
                meter(ui, fraction, color, "Waiting for a CPU sample");
                ui.label(
                    RichText::new("100% = one host CPU core")
                        .small()
                        .color(theme::muted()),
                );
            });
            place(ui, columns, &mut index, card_width, |ui| {
                memory_meter(ui, resources)
            });
            place(ui, columns, &mut index, card_width, |ui| {
                ui.label(RichText::new("Configured guest RAM").strong());
                row(ui, "Capacity", format!("{} MiB", vm.ram_mib));
                ui.add(
                    egui::Label::new(
                        RichText::new("guest RAM utilization is unavailable").color(theme::muted()),
                    )
                    .wrap(),
                );
                meter(ui, None, theme::muted(), "No guest RAM usage telemetry");
            });
            place(ui, columns, &mut index, card_width, |ui| disk_meter(ui, resources));
            place(ui, columns, &mut index, card_width, |ui| {
                ui.label(RichText::new("Capture quota").strong());
                row(ui, "Configured limit", format!("{quota_gib} GiB"));
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Recording limit for this monitor. The footer CAP counter is bytes stored.",
                        )
                        .color(theme::muted()),
                    )
                    .wrap(),
                );
            });
            if index % columns != 0 {
                ui.end_row();
            }
        });
    row(
        ui,
        "VM uptime",
        resources
            .uptime_ms
            .map_or_else(|| "Unavailable".into(), uptime),
    );
    ui.add(
        egui::Label::new(
            RichText::new(
                "QEMU CPU and RSS include host overhead. Guest RAM utilization is unavailable.",
            )
            .color(theme::muted()),
        )
        .wrap(),
    );
    if let Some(error) = &resources.sample_error {
        ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
    }
}

fn place(
    ui: &mut egui::Ui,
    columns: usize,
    index: &mut usize,
    width: f32,
    body: impl FnOnce(&mut egui::Ui),
) {
    card(ui, width, body);
    *index += 1;
    if *index % columns == 0 {
        ui.end_row();
    }
}

fn card(ui: &mut egui::Ui, width: f32, body: impl FnOnce(&mut egui::Ui)) {
    let min_height = ui.text_style_height(&egui::TextStyle::Body) * 8.2;
    ui.allocate_ui_with_layout(
        egui::vec2(width, min_height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_width(width);
            egui::Frame::new()
                .fill(theme::raised())
                .stroke(egui::Stroke::new(1.0_f32, theme::line()))
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_min_width((width - 22.0).max(80.0));
                    ui.set_min_height((min_height - 22.0).max(72.0));
                    body(ui);
                });
        },
    );
}

fn cpu_chart(
    ui: &mut egui::Ui,
    history: &CpuHistory,
    resources: Option<&VmResources>,
    retained: Option<&RetainedSample>,
    cpus: u16,
) {
    let _ = (resources, retained);
    let scale = history.scale(cpus);
    ui.add(egui::Label::new(RichText::new(format!("Recent 60 samples · Scale 0–{scale:.0}%")).color(theme::muted())).wrap())
        .on_hover_text("Samples are retained while Summary is visible. Missing observations break the line; they are not zero CPU usage. The graph starts at the configured vCPU scale and expands for QEMU overhead.");
    let height = (ui.text_style_height(&egui::TextStyle::Body) * 5.0).max(120.0);
    let (response, painter) = ui.allocate_painter(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let font = egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Small));
    let label_width = 48.0_f32.min(response.rect.width() * 0.2);
    let plot = egui::Rect::from_min_max(
        response.rect.min + egui::vec2(label_width, 2.0),
        response.rect.max - egui::vec2(4.0, font.size + 6.0),
    );
    painter.rect_filled(plot, 3.0, theme::bg());
    painter.rect_stroke(
        plot,
        3.0,
        egui::Stroke::new(1.0_f32, theme::line()),
        egui::StrokeKind::Inside,
    );
    painter.text(
        egui::pos2(response.rect.left(), plot.top()),
        egui::Align2::LEFT_TOP,
        format!("{scale:.0}%"),
        font.clone(),
        theme::muted(),
    );
    painter.text(
        egui::pos2(response.rect.left(), plot.center().y),
        egui::Align2::LEFT_CENTER,
        format!("{:.0}%", scale / 2.0),
        font.clone(),
        theme::muted(),
    );
    painter.text(
        egui::pos2(response.rect.left(), plot.bottom()),
        egui::Align2::LEFT_BOTTOM,
        "0%",
        font.clone(),
        theme::muted(),
    );
    let older = history
        .times
        .iter()
        .flatten()
        .next()
        .map(|instant| format!("{} s ago", instant.elapsed().as_secs()))
        .unwrap_or_else(|| "older".into());
    painter.text(
        egui::pos2(plot.left(), plot.bottom() + 2.0),
        egui::Align2::LEFT_TOP,
        older,
        font.clone(),
        theme::muted(),
    );
    painter.text(
        egui::pos2(plot.right(), plot.bottom() + 2.0),
        egui::Align2::RIGHT_TOP,
        "now",
        font.clone(),
        theme::muted(),
    );
    for step in 1..4 {
        let y = plot.bottom() - plot.height() * step as f32 / 4.0;
        painter.line_segment(
            [egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)],
            egui::Stroke::new(0.5_f32, theme::line()),
        );
    }
    let mut previous: Option<(egui::Pos2, f64)> = None;
    let start = HISTORY_LIMIT - history.samples.len();
    for (index, value) in history.samples.iter().enumerate() {
        let Some(value) = value else {
            previous = None;
            continue;
        };
        let point = egui::pos2(
            plot.left() + plot.width() * (start + index) as f32 / (HISTORY_LIMIT - 1) as f32,
            plot.bottom() - plot.height() * (value / scale).clamp(0.0, 1.0) as f32,
        );
        let color = cpu_load_color(*value, cpus);
        if let Some((before, _)) = previous {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(before.x, plot.bottom()),
                    before,
                    point,
                    egui::pos2(point.x, plot.bottom()),
                ],
                egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 35),
                egui::Stroke::NONE,
            ));
            painter.line_segment([before, point], egui::Stroke::new(1.8_f32, color));
        } else {
            painter.circle_filled(point, 2.0, color);
        }
        previous = Some((point, *value));
    }
    if let Some(pointer) = response.hover_pos() {
        if let Some((value, when)) = nearest_sample(history, plot, pointer.x) {
            let when = when
                .map(|instant| format!("{} s ago", instant.elapsed().as_secs()))
                .unwrap_or_else(|| "sample".into());
            response
                .clone()
                .on_hover_text(format!("{value:.1}% · {when}"));
        }
    }
}

fn nearest_sample(
    history: &CpuHistory,
    plot: egui::Rect,
    x: f32,
) -> Option<(f64, Option<Instant>)> {
    let start = HISTORY_LIMIT - history.samples.len();
    let mut best: Option<(f32, f64, Option<Instant>)> = None;
    for (index, value) in history.samples.iter().enumerate() {
        let Some(value) = value else {
            continue;
        };
        let point_x =
            plot.left() + plot.width() * (start + index) as f32 / (HISTORY_LIMIT - 1) as f32;
        let distance = (point_x - x).abs();
        let when = history.times.get(index).copied().flatten();
        if best
            .as_ref()
            .is_none_or(|(best_distance, _, _)| distance < *best_distance)
        {
            best = Some((distance, *value, when));
        }
    }
    best.map(|(_, value, when)| (value, when))
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
    painter.rect_filled(rect, 3.0, theme::bg());
    painter.rect_stroke(
        rect,
        3.0,
        egui::Stroke::new(1.0_f32, theme::line()),
        egui::StrokeKind::Inside,
    );
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
    ui.label(RichText::new("QEMU RSS").strong());
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
    ui.label(RichText::new("Host data volume").strong());
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
    ui.horizontal(|ui| {
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
        let mut stopped = snapshot.clone();
        stopped.active_vm = None;
        stopped.state = VmState::Stopped;
        history.observe(&stopped, Some("active"));
        assert_eq!(history.samples.len(), 1);
        assert!(history.retained.is_some());
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
        let mut history = CpuHistory::default();
        history.observe(snapshot, selected);
        let mut output = egui::FullOutput::default();
        for _ in 0..3 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        show(ui, snapshot, selected, 4, &history)
                    });
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
            history: CpuHistory,
            deadline: Instant,
        }
        impl eframe::App for Fixture {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                self.history.observe(&self.snapshot, Some("active"));
                egui::CentralPanel::default().show(ctx, |ui| {
                    show(ui, &self.snapshot, Some("active"), 4, &self.history)
                });
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let wide = std::env::var_os("ANTINOMIE_SUMMARY_QA_WIDE").is_some();
        let font = std::env::var("ANTINOMIE_SUMMARY_QA_FONT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(if wide { 16.0 } else { 24.0 });
        let seconds = std::env::var("ANTINOMIE_SUMMARY_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(12)
            .clamp(1, 120);
        let size = if wide {
            [1280.0, 860.0]
        } else {
            [520.0, 900.0]
        };
        eframe::run_native(
            "Antinomie Summary QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(size)
                    .with_position([48.0, 48.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, font);
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
                Ok(Box::new(Fixture {
                    snapshot,
                    history,
                    deadline: Instant::now() + Duration::from_secs(seconds),
                }))
            }),
        )
        .unwrap();
    }
}
