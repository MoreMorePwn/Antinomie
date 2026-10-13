// SPDX-License-Identifier: MIT
//! Native per-VM operational dashboard. Host observations never imply guest utilization.
use crate::theme;
use antinomie_monitor_core::{Snapshot, VmConfig, VmResources, VmState};
use eframe::egui::{self, Color32, RichText};
use std::collections::{BTreeMap, VecDeque};
use std::ops::Deref;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HISTORY_LIMIT: usize = 120;
const SESSION_LIMIT: usize = 16;
const WINDOW: Duration = Duration::from_secs(120);

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
pub(crate) struct VmHistory {
    identity: Option<(String, Option<String>)>,
    sequence: Option<u64>,
    uptime_ms: Option<u64>,
    samples: VecDeque<Option<f64>>,
    times: VecDeque<Option<Instant>>,
    residents: VecDeque<Option<f64>>,
    disk_available: VecDeque<Option<f64>>,
    retained: Option<RetainedSample>,
    stopped_at: Option<SystemTime>,
    last_gap: Option<Instant>,
}
#[derive(Clone, Default)]
pub(crate) struct CpuHistory {
    sessions: BTreeMap<String, VmHistory>,
    selected: Option<String>,
}
impl Deref for CpuHistory {
    type Target = VmHistory;
    fn deref(&self) -> &VmHistory {
        static EMPTY: LazyLock<VmHistory> = LazyLock::new(VmHistory::default);
        self.selected
            .as_ref()
            .and_then(|id| self.sessions.get(id))
            .unwrap_or(&EMPTY)
    }
}
impl CpuHistory {
    pub(crate) fn observe(&mut self, snapshot: &Snapshot, selected: Option<&str>) {
        self.observe_at(snapshot, selected, Instant::now());
    }
    fn observe_at(&mut self, snapshot: &Snapshot, selected: Option<&str>, now: Instant) {
        self.selected = selected.map(str::to_owned);
        let running = matches!(
            snapshot.state,
            VmState::Running | VmState::Starting | VmState::Stopping
        );
        let active = snapshot.active_vm.as_deref().filter(|_| running);
        for (id, series) in &mut self.sessions {
            if Some(id.as_str()) != active && series.stopped_at.is_none() {
                series.stopped_at = Some(SystemTime::now());
            }
        }
        let Some(id) = active else {
            return;
        };
        let sample = snapshot
            .vm_resources
            .as_ref()
            .filter(|sample| sample.vm_id == id);
        if !self.sessions.contains_key(id) && self.sessions.len() >= SESSION_LIMIT {
            let oldest = self
                .sessions
                .iter()
                .filter(|(key, _)| key.as_str() != id)
                .min_by_key(|(_, value)| value.retained.as_ref().map(|sample| sample.seen))
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.sessions.remove(&oldest);
            }
        }
        let series = self.sessions.entry(id.to_owned()).or_default();
        let previous_boot = series.identity.as_ref().and_then(|(_, boot)| boot.clone());
        if snapshot
            .boot_id
            .as_ref()
            .is_some_and(|after| previous_boot.as_ref() != Some(after))
        {
            *series = VmHistory::default();
        }
        series.identity = Some((id.to_owned(), snapshot.boot_id.clone().or(previous_boot)));
        series.stopped_at = None;
        let Some(sample) = sample else {
            if series.retained.as_ref().is_some_and(|last| {
                now.saturating_duration_since(last.seen) >= Duration::from_secs(1)
            }) && series
                .last_gap
                .is_none_or(|last| now.saturating_duration_since(last) >= Duration::from_secs(1))
            {
                series.push(now, None, None, None);
                series.last_gap = Some(now);
            }
            return;
        };
        if series.sequence == Some(sample.sample_sequence) {
            return;
        }
        let restarted = series
            .sequence
            .is_some_and(|previous| sample.sample_sequence < previous)
            || series
                .uptime_ms
                .zip(sample.uptime_ms)
                .is_some_and(|(before, after)| after < before);
        if restarted {
            *series = VmHistory {
                identity: series.identity.clone(),
                ..Default::default()
            };
        }
        if let Some(previous) = series.sequence {
            let gap_count = sample
                .sample_sequence
                .saturating_sub(previous)
                .saturating_sub(1)
                .min(HISTORY_LIMIT as u64);
            let old_time = series.times.back().copied().flatten().unwrap_or(now);
            let span = now.saturating_duration_since(old_time);
            for gap in 0..gap_count {
                let part = (gap + 1) as f64 / (gap_count + 1) as f64;
                series.push(old_time + span.mul_f64(part), None, None, None);
            }
        }
        series.push(
            now,
            cpu_value(sample.qemu_cpu_percent),
            sample.qemu_resident_size.map(|value| value as f64),
            sample.data_disk_available_size.map(|value| value as f64),
        );
        series.retained = Some(RetainedSample {
            cpu: cpu_value(sample.qemu_cpu_percent),
            rss: sample.qemu_resident_size,
            host_ram: sample.host_memory_total_size,
            disk_free: sample.data_disk_available_size,
            disk_total: sample.data_disk_total_size,
            uptime_ms: sample.uptime_ms,
            error: sample.sample_error.clone(),
            seen: now,
        });
        series.sequence = Some(sample.sample_sequence);
        series.uptime_ms = sample.uptime_ms.or(series.uptime_ms);
        series.last_gap = None;
    }
    fn for_vm(&self, id: &str) -> Option<&VmHistory> {
        self.sessions.get(id)
    }
}
impl VmHistory {
    fn push(&mut self, time: Instant, cpu: Option<f64>, rss: Option<f64>, disk: Option<f64>) {
        if self.samples.len() == HISTORY_LIMIT {
            self.samples.pop_front();
            self.times.pop_front();
            self.residents.pop_front();
            self.disk_available.pop_front();
        }
        self.samples.push_back(cpu);
        self.times.push_back(Some(time));
        self.residents.push_back(rss);
        self.disk_available.push_back(disk);
    }
    fn scale(&self, cpus: u16) -> f64 {
        let peak = self
            .samples
            .iter()
            .flatten()
            .copied()
            .fold(f64::from(cpus.max(1)) * 100.0, f64::max);
        (peak / 100.0).ceil() * 100.0
    }
}
fn cpu_value(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value >= 0.0)
}
fn fraction(value: Option<u64>, total: Option<u64>) -> Option<f64> {
    value
        .zip(total.filter(|total| *total > 0))
        .map(|(value, total)| value as f64 / total as f64)
}
fn accent(index: usize) -> Color32 {
    match index {
        0 => Color32::from_rgb(234, 174, 79),
        1 => Color32::from_rgb(82, 190, 184),
        _ => Color32::from_rgb(115, 153, 213),
    }
}
fn cpu_load_color(percent: f64, cpus: u16) -> Color32 {
    let fraction = percent / (f64::from(cpus.max(1)) * 100.0);
    if fraction >= 1.0 {
        theme::error()
    } else if fraction >= 0.8 {
        theme::warn()
    } else {
        accent(0)
    }
}
pub(crate) fn show(
    ui: &mut egui::Ui,
    snapshot: &Snapshot,
    selected: Option<&str>,
    quota_gib: u32,
    history: &CpuHistory,
) {
    let width = ui.available_width();
    egui::ScrollArea::vertical()
        .id_salt("vm-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_max_width(width);
            let Some(vm) = selected.and_then(|id| snapshot.vms.iter().find(|vm| vm.id == id))
            else {
                ui.heading("Select a VM");
                ui.label("Choose a VM to see its status, resources and recording health.");
                if snapshot.vms.is_empty() {
                    ui.label("Create a VM from File → New VM, or add a base first.");
                }
                return;
            };
            let active = snapshot.active_vm.as_deref() == Some(vm.id.as_str())
                && snapshot.state != VmState::Stopped;
            let narrow = width < ui.text_style_height(&egui::TextStyle::Body) * 32.0;
            if narrow {
                ui.add(egui::Label::new(RichText::new(&vm.name).heading().strong()).wrap());
            }
            ui.horizontal_wrapped(|ui| {
                if !narrow {
                    ui.add(
                        egui::Label::new(
                            RichText::new(&vm.name)
                                .size(ui.text_style_height(&egui::TextStyle::Heading))
                                .strong(),
                        )
                        .wrap(),
                    );
                }
                indicator(
                    ui,
                    state_label(snapshot, active),
                    state_color(snapshot, active),
                );
                ui.colored_label(theme::muted(), format!("{} vCPU", vm.cpus));
                ui.colored_label(theme::muted(), network_label(vm));
            });
            if let Some(base) = crate::app::selected_base(snapshot, vm.base_identity.as_deref()) {
                ui.add(
                    egui::Label::new(RichText::new(&base.label).small().color(theme::muted()))
                        .wrap(),
                );
            }
            let series = history.for_vm(&vm.id);
            let live = active
                .then_some(snapshot.vm_resources.as_ref())
                .flatten()
                .filter(|sample| sample.vm_id == vm.id);
            let retained = series.and_then(|series| series.retained.as_ref());
            let fallback = retained.map(|last| retained_resources(last, &vm.id));
            let resources = live.or(fallback.as_ref());
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(theme::muted(), "Resources");
                if let Some(sample) = resources {
                    if let Some(value) = sample.uptime_ms {
                        ui.colored_label(theme::muted(), uptime(value));
                    }
                }
                if live.is_some() {
                    ui.colored_label(theme::good(), "Live");
                } else if let Some(last) = retained {
                    ui.colored_label(
                        theme::muted(),
                        format!("Last observation {}", age(last.seen)),
                    );
                    if let Some(stopped) = series.and_then(|series| series.stopped_at) {
                        ui.colored_label(
                            theme::muted(),
                            format!("Stopped {}", format_utc(stopped)),
                        );
                    }
                } else {
                    ui.colored_label(
                        theme::muted(),
                        if active {
                            "Waiting for the first resource sample"
                        } else {
                            "No retained observation"
                        },
                    );
                }
            });
            ui.add_space(6.0);
            let empty = VmResources {
                vm_id: vm.id.clone(),
                ..Default::default()
            };
            let values = resources.unwrap_or(&empty);
            let columns = if width >= ui.text_style_height(&egui::TextStyle::Body) * 48.0 {
                3
            } else if width >= ui.text_style_height(&egui::TextStyle::Body) * 32.0 {
                2
            } else {
                1
            };
            let gap = 10.0;
            let panel_width = ((width - gap * (columns - 1) as f32) / columns as f32).max(80.0);
            egui::Grid::new("summary-resources")
                .num_columns(columns)
                .spacing(egui::vec2(gap, gap))
                .show(ui, |ui| {
                    for kind in 0..3 {
                        resource_panel(ui, panel_width, kind, values, vm, series);
                        if (kind + 1) % columns == 0 {
                            ui.end_row();
                        }
                    }
                    if 3 % columns != 0 {
                        ui.end_row();
                    }
                });
            ui.add_space(10.0);
            egui::Frame::new()
                .fill(theme::bg())
                .stroke(egui::Stroke::new(1.0_f32, theme::line()))
                .inner_margin(10)
                .show(ui, |ui| {
                    ui.set_min_width((width - 22.0).max(80.0));
                    ui.horizontal_wrapped(|ui| {
                        ui.strong("Capture storage");
                        ui.label(if active {
                            format!("{} / {quota_gib} GiB", size(snapshot.health.persisted_len))
                        } else {
                            format!("Limit {quota_gib} GiB")
                        });
                        ui.colored_label(theme::muted(), "Retained recording quota");
                    });
                    if active {
                        meter(
                            ui,
                            fraction(
                                Some(snapshot.health.persisted_len),
                                Some(u64::from(quota_gib) * 1_073_741_824),
                            ),
                            theme::blue(),
                            "Quota unavailable",
                        );
                    }
                });
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                ui.strong("Health");
                if active {
                    let (label, color) = health_state(snapshot);
                    indicator(ui, label, color);
                } else {
                    ui.colored_label(theme::muted(), "No live health observation");
                }
            });
            if active {
                ui.horizontal_wrapped(|ui| {
                    for (label, value) in [
                        ("Transport drops", snapshot.health.dropped),
                        ("Storage drops", snapshot.health.storage_dropped_packets),
                        ("UI preview drops", snapshot.health.ui_dropped),
                    ] {
                        ui.colored_label(
                            if value == 0 {
                                theme::muted()
                            } else {
                                theme::warn()
                            },
                            format!("{label}: {value}"),
                        );
                    }
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
                if let Some(error) = &snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::error())).wrap());
                }
                egui::CollapsingHeader::new("More health details")
                    .show(ui, |ui| health(ui, snapshot));
            }
            if let Some(error) = resources.and_then(|sample| sample.sample_error.as_ref()) {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
        });
}
fn resource_panel(
    ui: &mut egui::Ui,
    width: f32,
    kind: usize,
    sample: &VmResources,
    vm: &VmConfig,
    history: Option<&VmHistory>,
) {
    egui::Frame::new()
        .fill(theme::bg())
        .stroke(egui::Stroke::new(1.0_f32, theme::line()))
        .inner_margin(12)
        .show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                let inner = (width - 26.0).max(54.0);
                ui.set_min_width(inner);
                ui.set_max_width(inner);
                let (title, value, unit, ratio, note) = match kind {
                    0 => (
                        "QEMU host CPU",
                        cpu_value(sample.qemu_cpu_percent).map(|v| format!("{v:.1}")),
                        "%",
                        cpu_value(sample.qemu_cpu_percent)
                            .map(|v| v / (f64::from(vm.cpus.max(1)) * 100.0)),
                        format!("{} vCPU capacity · 100% = one host core", vm.cpus),
                    ),
                    1 => {
                        let (v, u) = split_size(sample.qemu_resident_size);
                        (
                            "QEMU resident memory",
                            v,
                            u,
                            fraction(sample.qemu_resident_size, sample.host_memory_total_size),
                            format!(
                                "Guest capacity {} · host visible {}",
                                size(u64::from(vm.ram_mib) * 1_048_576),
                                optional_size(sample.host_memory_total_size)
                            ),
                        )
                    }
                    _ => {
                        let (v, u) = split_size(sample.data_disk_available_size);
                        (
                            "Host data volume free",
                            v,
                            u,
                            sample
                                .data_disk_available_size
                                .zip(sample.data_disk_total_size)
                                .filter(|(a, t)| a <= t)
                                .and_then(|(a, t)| fraction(Some(a), Some(t))),
                            format!(
                                "{} volume · {} guest disk",
                                optional_size(sample.data_disk_total_size),
                                size(u64::from(vm.disk_gib) * 1_073_741_824)
                            ),
                        )
                    }
                };
                ui.strong(title);
                let font = ui.text_style_height(&egui::TextStyle::Body);
                let color = if kind == 0 {
                    sample
                        .qemu_cpu_percent
                        .map(|v| cpu_load_color(v, vm.cpus))
                        .unwrap_or_else(theme::muted)
                } else {
                    accent(kind)
                };
                gauge(
                    ui,
                    ratio,
                    value.as_deref().unwrap_or("—"),
                    unit,
                    color,
                    inner,
                    (font * 6.0).clamp(96.0, 160.0),
                );
                ui.add(egui::Label::new(RichText::new(note).small().color(theme::muted())).wrap());
                if value.is_none() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("Unavailable measurement")
                                .small()
                                .color(theme::muted()),
                        )
                        .wrap(),
                    );
                } else if ratio.is_none() {
                    ui.add(
                        egui::Label::new(
                            RichText::new("Capacity unavailable")
                                .small()
                                .color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
                ui.add_space(5.0);
                let (data, scale) = if let Some(series) = history {
                    match kind {
                        0 => (&series.samples, series.scale(vm.cpus)),
                        1 => (
                            &series.residents,
                            sample
                                .host_memory_total_size
                                .map(|v| v as f64)
                                .unwrap_or_else(|| {
                                    series
                                        .residents
                                        .iter()
                                        .flatten()
                                        .copied()
                                        .fold(1.0, f64::max)
                                }),
                        ),
                        _ => (
                            &series.disk_available,
                            sample
                                .data_disk_total_size
                                .map(|v| v as f64)
                                .unwrap_or_else(|| {
                                    series
                                        .disk_available
                                        .iter()
                                        .flatten()
                                        .copied()
                                        .fold(1.0, f64::max)
                                }),
                        ),
                    }
                } else {
                    (&VecDeque::new(), 1.0)
                };
                trend(
                    ui,
                    history,
                    data,
                    scale,
                    kind,
                    color,
                    (font * 5.0).clamp(88.0, 140.0),
                );
                if kind == 1 {
                    ui.add(
                        egui::Label::new(
                            RichText::new("Guest RAM utilization unavailable")
                                .small()
                                .color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
            });
        });
}
fn gauge(
    ui: &mut egui::Ui,
    ratio: Option<f64>,
    value: &str,
    unit: &str,
    color: Color32,
    width: f32,
    height: f32,
) {
    let (response, painter) = ui.allocate_painter(egui::vec2(width, height), egui::Sense::hover());
    let radius = (width * 0.40).min(height * 0.77).max(12.0);
    let center = egui::pos2(response.rect.center().x, response.rect.top() + radius + 5.0);
    let arc = |part: f64| -> Vec<egui::Pos2> {
        (0..=48)
            .map(|n| {
                let angle =
                    std::f32::consts::PI + (n as f32 / 48.0) * std::f32::consts::PI * part as f32;
                center + egui::vec2(angle.cos() * radius, angle.sin() * radius)
            })
            .collect()
    };
    painter.add(egui::Shape::line(
        arc(1.0),
        egui::Stroke::new(6.0_f32, theme::line()),
    ));
    if let Some(part) = ratio.filter(|v| v.is_finite()) {
        painter.add(egui::Shape::line(
            arc(part.clamp(0.0, 1.0)),
            egui::Stroke::new(6.0_f32, color),
        ));
    }
    let number_font = egui::FontId::proportional((radius * 0.45).clamp(24.0, 46.0));
    painter.text(
        center - egui::vec2(0.0, 8.0),
        egui::Align2::CENTER_BOTTOM,
        value,
        number_font,
        if ratio.is_some() {
            theme::text()
        } else {
            theme::muted()
        },
    );
    painter.text(
        center + egui::vec2(0.0, 4.0),
        egui::Align2::CENTER_TOP,
        unit,
        egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Small)),
        theme::muted(),
    );
    response.on_hover_text(if let Some(value) = ratio {
        format!("{:.1}% of the labeled capacity", value * 100.0)
    } else {
        "Unavailable observation or capacity; not zero".into()
    });
}
fn trend(
    ui: &mut egui::Ui,
    history: Option<&VmHistory>,
    values: &VecDeque<Option<f64>>,
    scale: f64,
    kind: usize,
    color: Color32,
    height: f32,
) {
    let (response, painter) = ui.allocate_painter(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let font = egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Small));
    let plot = egui::Rect::from_min_max(
        response.rect.min + egui::vec2(3.0, font.size + 3.0),
        response.rect.max - egui::vec2(3.0, font.size + 4.0),
    );
    let top = if !values
        .iter()
        .any(|value| value.is_some_and(|value| value.is_finite()))
    {
        "—".into()
    } else if kind == 0 {
        format!("{scale:.0}%")
    } else {
        size(scale.max(0.0) as u64)
    };
    painter.text(
        response.rect.min,
        egui::Align2::LEFT_TOP,
        top,
        font.clone(),
        theme::muted(),
    );
    for n in 0..=3 {
        let y = plot.top() + plot.height() * n as f32 / 3.0;
        painter.line_segment(
            [egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)],
            egui::Stroke::new(0.6_f32, theme::line()),
        );
    }
    let anchor = history
        .and_then(|h| h.times.back().copied().flatten())
        .unwrap_or_else(Instant::now);
    let start = anchor.checked_sub(WINDOW).unwrap_or(anchor);
    let mut previous: Option<egui::Pos2> = None;
    let mut closest: Option<(f32, f64, Instant)> = None;
    if let Some(history) = history {
        for (value, time) in values.iter().zip(&history.times) {
            let Some(time) = time else {
                previous = None;
                continue;
            };
            let Some(value) = value.filter(|v| v.is_finite()) else {
                previous = None;
                continue;
            };
            if *time < start {
                previous = None;
                continue;
            }
            let x = plot.left()
                + plot.width() * time.saturating_duration_since(start).as_secs_f64() as f32
                    / WINDOW.as_secs_f32();
            let point = egui::pos2(
                x,
                plot.bottom() - plot.height() * (value / scale.max(1.0)).clamp(0.0, 1.0) as f32,
            );
            if let Some(before) = previous {
                painter.line_segment([before, point], egui::Stroke::new(1.8_f32, color));
                painter.add(egui::Shape::convex_polygon(
                    vec![
                        egui::pos2(before.x, plot.bottom()),
                        before,
                        point,
                        egui::pos2(point.x, plot.bottom()),
                    ],
                    color.linear_multiply(0.08),
                    egui::Stroke::NONE,
                ));
            }
            previous = Some(point);
            if let Some(mouse) = response.hover_pos() {
                let distance = (mouse.x - x).abs();
                if closest.is_none_or(|(old, _, _)| distance < old) {
                    closest = Some((distance, value, *time));
                }
            }
        }
    }
    painter.text(
        egui::pos2(plot.left(), response.rect.bottom()),
        egui::Align2::LEFT_BOTTOM,
        "−2 min",
        font.clone(),
        theme::muted(),
    );
    painter.text(
        egui::pos2(plot.right(), response.rect.bottom()),
        egui::Align2::RIGHT_BOTTOM,
        if history.is_some_and(|h| h.stopped_at.is_some()) {
            "last"
        } else {
            "now"
        },
        font,
        theme::muted(),
    );
    if let Some((_, value, time)) = closest {
        response.on_hover_text(format!(
            "{} · {}",
            if kind == 0 {
                format!("{value:.1}%")
            } else {
                size(value as u64)
            },
            age(time)
        ));
    }
}
fn indicator(ui: &mut egui::Ui, label: &str, color: Color32) {
    ui.add(egui::Label::new(RichText::new(format!("● {label}")).color(color)).wrap());
}
fn meter(ui: &mut egui::Ui, ratio: Option<f64>, color: Color32, unavailable: &str) {
    let (response, painter) =
        ui.allocate_painter(egui::vec2(ui.available_width(), 8.0), egui::Sense::hover());
    painter.rect_filled(response.rect, 2.0, theme::line());
    if let Some(ratio) = ratio.filter(|v| v.is_finite()) {
        let filled = egui::Rect::from_min_size(
            response.rect.min,
            egui::vec2(
                response.rect.width() * ratio.clamp(0.0, 1.0) as f32,
                response.rect.height(),
            ),
        );
        painter.rect_filled(filled, 2.0, color);
    } else {
        response.on_hover_text(unavailable);
    }
}
fn retained_resources(last: &RetainedSample, id: &str) -> VmResources {
    VmResources {
        vm_id: id.into(),
        sample_sequence: 0,
        uptime_ms: last.uptime_ms,
        qemu_cpu_percent: last.cpu,
        qemu_resident_size: last.rss,
        host_memory_total_size: last.host_ram,
        data_disk_available_size: last.disk_free,
        data_disk_total_size: last.disk_total,
        sample_error: last.error.clone(),
    }
}
fn state_label(snapshot: &Snapshot, active: bool) -> &'static str {
    if !active {
        return "Stopped";
    }
    match snapshot.state {
        VmState::Running => "Running",
        VmState::Starting => "Starting",
        VmState::Stopping => "Stopping",
        VmState::Failed => "Failed",
        VmState::Stopped => "Stopped",
    }
}
fn state_color(snapshot: &Snapshot, active: bool) -> Color32 {
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
fn network_label(vm: &VmConfig) -> &'static str {
    if vm.isolated_network {
        "Isolated"
    } else if vm.nat {
        "NAT / external access"
    } else {
        "Disabled"
    }
}
fn health_state(snapshot: &Snapshot) -> (&'static str, Color32) {
    if snapshot.health.persistence_error.is_some() {
        ("Recording error", theme::error())
    } else if snapshot.health.dropped > 0
        || snapshot.health.ui_dropped > 0
        || snapshot.health.storage_dropped_packets > 0
        || snapshot.health.shedding
    {
        ("Loss observed", theme::warn())
    } else {
        ("No recorded losses", theme::good())
    }
}
fn health(ui: &mut egui::Ui, snapshot: &Snapshot) {
    let h = &snapshot.health;
    for (label, value) in [
        ("Packets persisted", h.persisted_packets.to_string()),
        ("Write backlog", size(h.write_backlog)),
        ("Parser errors", h.parser_errors.to_string()),
        ("Reply stalls", h.reply_stalls.to_string()),
    ] {
        ui.horizontal_wrapped(|ui| {
            ui.label(label);
            ui.monospace(value);
        });
    }
}
fn age(time: Instant) -> String {
    let seconds = time.elapsed().as_secs();
    if seconds < 60 {
        format!("{seconds} s ago")
    } else {
        format!("{} m ago", seconds / 60)
    }
}
fn format_utc(time: SystemTime) -> String {
    let Ok(d) = time.duration_since(UNIX_EPOCH) else {
        return "Unavailable".into();
    };
    let seconds = d.as_secs();
    let (y, m, day) = civil_from_days((seconds / 86400) as i64);
    format!(
        "{y:04}-{m:02}-{day:02} {:02}:{:02}:{:02} UTC",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + i64::from(m <= 2)) as i32, m as u32, d as u32)
}
fn split_size(value: Option<u64>) -> (Option<String>, &'static str) {
    let Some(value) = value else {
        return (None, "Unavailable");
    };
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = value as f64;
    let mut unit = 0;
    while n >= 1024.0 && unit < 4 {
        n /= 1024.0;
        unit += 1;
    }
    (
        Some(if unit == 0 {
            format!("{n:.0}")
        } else {
            format!("{n:.1}")
        }),
        UNITS[unit],
    )
}
fn size(value: u64) -> String {
    let (n, u) = split_size(Some(value));
    format!("{} {u}", n.unwrap_or_else(|| "—".into()))
}
fn optional_size(value: Option<u64>) -> String {
    value.map_or_else(|| "Unavailable".into(), size)
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
    fn transient_missing_boot_identity_preserves_observed_series() {
        let mut snapshot = fixture();
        snapshot.boot_id = Some("known-boot".into());
        let mut history = CpuHistory::default();
        history.observe(&snapshot, Some("active"));
        snapshot.boot_id = None;
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 2;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 2);
        assert_eq!(
            history.identity.as_ref().unwrap().1.as_deref(),
            Some("known-boot")
        );
        snapshot.boot_id = Some("known-boot".into());
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 3;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 3);
    }

    #[test]
    fn history_survives_selection_and_missing_observations_but_resets_on_new_boot() {
        let mut snapshot = fixture();
        let mut history = CpuHistory::default();
        let now = Instant::now();
        for sequence in 1..=HISTORY_LIMIT as u64 {
            snapshot.vm_resources.as_mut().unwrap().sample_sequence = sequence;
            history.observe_at(
                &snapshot,
                Some("active"),
                now + Duration::from_secs(sequence),
            );
        }
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        history.observe(&snapshot, Some("stopped"));
        assert!(history.samples.is_empty());
        assert_eq!(
            history.for_vm("active").unwrap().samples.len(),
            HISTORY_LIMIT
        );
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        let mut missing = snapshot.clone();
        missing.vm_resources = None;
        history.observe_at(&missing, Some("active"), now + Duration::from_secs(122));
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        assert!(history.retained.is_some());
        assert_eq!(history.samples.back(), Some(&None));
        let mut stopped = snapshot.clone();
        stopped.active_vm = None;
        stopped.state = VmState::Stopped;
        history.observe(&stopped, Some("active"));
        assert_eq!(history.samples.len(), HISTORY_LIMIT);
        assert!(history.stopped_at.is_some());
        snapshot.boot_id = Some("new-boot".into());
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence += 1;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 2);
        snapshot.vm_resources.as_mut().unwrap().sample_sequence = 1;
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
        snapshot.vm_resources.as_mut().unwrap().vm_id = "wrong-vm".into();
        history.observe(&snapshot, Some("active"));
        assert_eq!(history.samples.len(), 1);
    }

    #[test]
    fn collection_tracks_active_vm_when_its_dashboard_is_hidden() {
        let mut snapshot = fixture();
        let mut history = CpuHistory::default();
        history.observe(&snapshot, Some("stopped"));
        assert_eq!(history.for_vm("active").unwrap().samples.len(), 1);
        snapshot.active_vm = Some("stopped".into());
        snapshot.boot_id = Some("second-boot".into());
        snapshot.vm_resources.as_mut().unwrap().vm_id = "stopped".into();
        history.observe(&snapshot, None);
        assert_eq!(history.for_vm("stopped").unwrap().samples.len(), 1);
        assert_eq!(history.for_vm("active").unwrap().samples.len(), 1);
        assert!(history.for_vm("active").unwrap().stopped_at.is_some());
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
        assert!(text.contains("1.0") && text.contains("MiB"));
        assert!(text.contains("11.8") && text.contains("MiB"));
        assert!(text.contains("Capacity unavailable"));
        assert!(!text.contains("QEMU share:"));
        assert!(!text.contains("Available share:"));
        assert!(text.contains("Guest RAM utilization unavailable"));
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
                    egui::CentralPanel::default()
                        .show(ctx, |ui| show(ui, snapshot, selected, 4, &history));
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
        assert!(
            !texts
                .iter()
                .any(|(label, _)| label == "1 B" || label == "1%"),
            "an empty chart must not display its internal fallback scale as a measurement"
        );
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
        assert!(text.contains("123.4") && text.contains("100% = one host core"));
        assert!(text.contains("1 h 01 m 01 s"));
        assert!(text.contains("Guest RAM utilization unavailable"));
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
        assert!(text.contains("QEMU host CPU") && text.contains("Unavailable"));
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
    #[ignore = "requires X11 native rendering; bounded state/viewport fixture"]
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
        let state = std::env::var("ANTINOMIE_SUMMARY_QA_STATE").unwrap_or_else(|_| "active".into());
        assert!(
            matches!(state.as_str(), "active" | "stopped" | "unknown"),
            "ANTINOMIE_SUMMARY_QA_STATE must be active, stopped or unknown"
        );
        let font = std::env::var("ANTINOMIE_SUMMARY_QA_FONT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .filter(|font| font.is_finite())
            .unwrap_or(if wide { 16.0 } else { 24.0 })
            .clamp(8.0, 36.0);
        let seconds = std::env::var("ANTINOMIE_SUMMARY_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(12)
            .clamp(1, 120);
        let width = std::env::var("ANTINOMIE_SUMMARY_QA_WIDTH")
            .ok()
            .map(|value| {
                value
                    .parse::<u32>()
                    .expect("ANTINOMIE_SUMMARY_QA_WIDTH must be an integer")
            })
            .unwrap_or(if wide { 1280 } else { 520 })
            .clamp(320, 1920);
        let size = [width as f32, if width >= 960 { 860.0 } else { 900.0 }];
        println!("Summary native fixture: state={state}, width={width}, font={font}, duration={seconds}s");
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
                let observed_at = Instant::now()
                    - if state == "stopped" {
                        Duration::from_secs(30)
                    } else {
                        Duration::ZERO
                    };
                for sequence in 1..=if state == "unknown" {
                    0
                } else {
                    HISTORY_LIMIT as u64
                } {
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
                    history.observe_at(
                        &snapshot,
                        Some("active"),
                        observed_at - WINDOW + Duration::from_secs(sequence),
                    );
                }
                match state.as_str() {
                    "stopped" => {
                        snapshot.state = VmState::Stopped;
                        snapshot.active_vm = None;
                        snapshot.vm_resources = None;
                        history.observe(&snapshot, Some("active"));
                    }
                    "unknown" => {
                        // A running VM without any resource observation has no
                        // retained fallback, so the real view paints unknown values.
                        snapshot.vm_resources = None;
                    }
                    _ => {}
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
