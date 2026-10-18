// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Bounded UI timings and graphics context queried once at startup.
use crate::theme;
use eframe::{egui, glow::HasContext};
use std::{
    collections::VecDeque,
    path::Path,
    time::{Duration, Instant},
};

const SAMPLE_LIMIT: usize = 240;
/// Frames older than this no longer count toward the FPS counter.
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Hard cap on remembered frames, however fast the window repaints.
const FRAME_LIMIT: usize = 512;
/// Fewer frames than this in the window read as idle, not as a rate.
const BUSY_FRAMES: usize = 3;

/// Repaint rate over the last [`RATE_WINDOW`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FrameRate {
    pub(crate) fps: f64,
    /// Mean time between painted frames.
    pub(crate) frame_ms: f64,
    /// Mean UI build time of those frames.
    pub(crate) ui_ms: f64,
}

impl FrameRate {
    pub(crate) fn text(self) -> String {
        format!(
            "{:.0} fps \u{b7} {:.1} ms \u{b7} UI {:.2} ms",
            self.fps, self.frame_ms, self.ui_ms
        )
    }
}

#[derive(Default)]
pub(crate) struct Performance {
    pub(crate) open: bool,
    renderer: String,
    vendor: String,
    version: String,
    samples: VecDeque<f64>,
    last_frame: Option<Instant>,
    interval_ms: Option<f64>,
    error: Option<String>,
    /// When each recent frame was painted and its UI build time in ms.
    frames: VecDeque<(Instant, f64)>,
    /// The last rate measured while frames were arriving.
    last_rate: Option<FrameRate>,
}

impl Performance {
    #[cfg(test)]
    pub(crate) fn reset_for_probe(&mut self) {
        self.samples.clear();
        self.last_frame = None;
        self.interval_ms = None;
    }

    #[cfg(test)]
    pub(crate) fn probe_report(&self) -> serde_json::Value {
        let mut sorted: Vec<_> = self.samples.iter().copied().collect();
        sorted.sort_by(f64::total_cmp);
        serde_json::json!({"renderer": self.renderer, "samples": sorted.len(),
            "median_ui_ms": sorted.get(sorted.len()/2),
            "p95_ui_ms": sorted.get((sorted.len()*95).div_ceil(100).saturating_sub(1)),
            "total_ui_ms": sorted.iter().sum::<f64>()})
    }
    pub(crate) fn new(gl: Option<&eframe::glow::Context>) -> Self {
        let mut value = Self::default();
        if let Some(gl) = gl {
            // SAFETY: eframe calls app creation with this context current.
            // Read-only GL queries access no guest memory or raw pointers.
            unsafe {
                value.renderer = gl.get_parameter_string(eframe::glow::RENDERER);
                value.vendor = gl.get_parameter_string(eframe::glow::VENDOR);
                value.version = gl.get_parameter_string(eframe::glow::VERSION);
            }
        }
        value
    }

    pub(crate) fn record(&mut self, elapsed: Duration) {
        self.record_at(Instant::now(), elapsed);
    }

    pub(crate) fn record_at(&mut self, now: Instant, elapsed: Duration) {
        if self.samples.len() == SAMPLE_LIMIT {
            self.samples.pop_front();
        }
        let ui_ms = elapsed.as_secs_f64() * 1000.0;
        self.samples.push_back(ui_ms);
        while self
            .frames
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) > RATE_WINDOW)
            || self.frames.len() >= FRAME_LIMIT
        {
            self.frames.pop_front();
        }
        self.frames.push_back((now, ui_ms));
        self.interval_ms = self
            .last_frame
            .map(|last| now.duration_since(last).as_secs_f64() * 1000.0);
        self.last_frame = Some(now);
    }

    /// The repaint rate at `now`, or `None` when too few frames were painted
    /// in the last second. It only reads frames that were painted anyway.
    pub(crate) fn frame_rate(&self, now: Instant) -> Option<FrameRate> {
        let recent: Vec<_> = self
            .frames
            .iter()
            .filter(|(at, _)| now.saturating_duration_since(*at) <= RATE_WINDOW)
            .collect();
        let (first, last) = (recent.first()?.0, recent.last()?.0);
        let span = last.saturating_duration_since(first).as_secs_f64();
        if recent.len() < BUSY_FRAMES || span <= 0.0 {
            return None;
        }
        let intervals = (recent.len() - 1) as f64;
        Some(FrameRate {
            fps: intervals / span,
            frame_ms: span * 1000.0 / intervals,
            ui_ms: recent.iter().map(|(_, ms)| ms).sum::<f64>() / recent.len() as f64,
        })
    }

    /// The text of the FPS overlay and whether it is a live reading.
    pub(crate) fn fps_label(&mut self, now: Instant) -> (String, bool) {
        if let Some(rate) = self.frame_rate(now) {
            self.last_rate = Some(rate);
            return (rate.text(), true);
        }
        match self.last_rate {
            Some(rate) => (format!("idle \u{b7} last {:.0} fps", rate.fps), false),
            None => ("idle".to_owned(), false),
        }
    }

    /// Draws the FPS counter in the top-right corner, beside the menu bar. It never requests a
    /// repaint: the number is the real repaint rate, and an idle window shows
    /// "idle" on the app's own slow cadence.
    pub(crate) fn show_fps(&mut self, ctx: &egui::Context) {
        let (label, live) = self.fps_label(Instant::now());
        // Painted directly, not as an `Area`: an area sizes itself one frame
        // late and asks egui for a second pass whenever its text changes width.
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("fps-counter"),
        ));
        let color = if live { theme::text() } else { theme::muted() };
        let font = egui::TextStyle::Monospace.resolve(&ctx.style());
        let galley =
            painter.layout_no_wrap(label, egui::FontId::monospace(font.size * 0.85), color);
        let padding = egui::vec2(6.0, 2.0);
        let rect = egui::Align2::RIGHT_TOP.align_size_within_rect(
            galley.size() + padding * 2.0,
            ctx.screen_rect().shrink2(egui::vec2(8.0, 4.0)),
        );
        painter.rect_filled(rect, 4.0, theme::raised());
        painter.rect_stroke(
            rect,
            4.0,
            egui::Stroke::new(1.0_f32, theme::line()),
            egui::StrokeKind::Inside,
        );
        painter.galley(rect.min + padding, galley, color);
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context, data_dir: &Path) {
        if !self.open {
            return;
        }
        egui::Window::new("UI performance").id(egui::Id::new("ui-performance"))
            .open(&mut self.open).default_width(530.0).resizable(true).show(ctx, |ui| {
                ui.strong("Graphics");
                ui.add(egui::Label::new(format!("Renderer: {}", if self.renderer.is_empty() { "Unavailable" } else { &self.renderer })).wrap());
                ui.add(egui::Label::new(format!("Vendor: {}", self.vendor)).wrap());
                ui.add(egui::Label::new(format!("OpenGL: {}", self.version)).wrap());
                if software_renderer(&self.renderer) {
                    crate::activity::warning(ui, "Software rendering uses the CPU and can slow the whole window.");
                }
                if ui.button("Copy WSL D3D12 launch command").clicked() {
                    match std::env::current_exe().and_then(|exe| std::path::absolute(data_dir).map(|data| (exe, data))) {
                        Ok((exe, data)) => match launch_command(&exe, &data) {
                            Ok(command) => ctx.copy_text(command),
                            Err(error) => self.error = Some(error.into()),
                        },
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                ui.add(egui::Label::new("For WSLg with a compatible GPU driver. Close Antinomie normally before using the command. It applies only to that launch.").wrap());
                if let Some(error) = &self.error { crate::activity::error(ui, error); }
                ui.separator();
                ui.strong("UI update CPU time");
                let mut sorted: Vec<_> = self.samples.iter().copied().collect();
                sorted.sort_by(f64::total_cmp);
                if !sorted.is_empty() {
                    let median = sorted[sorted.len() / 2];
                    let p95 = sorted[(sorted.len() * 95).div_ceil(100).saturating_sub(1)];
                    ui.label(format!("Median {median:.2} ms · p95 {p95:.2} ms · {} samples", sorted.len()));
                }
                if let Some(interval) = self.interval_ms { ui.label(format!("Last update interval: {interval:.1} ms")); }
                ui.add(egui::Label::new("App update/layout work, excluding GPU rendering and presentation. Idle intervals are intentional; they are not frame latency.").wrap());
                if ui.button("Reset timings").clicked() { self.samples.clear(); self.last_frame = None; }
            });
        if self.open {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }
}

fn software_renderer(renderer: &str) -> bool {
    let renderer = renderer.to_ascii_lowercase();
    ["llvmpipe", "softpipe", "swrast", "software rasterizer"]
        .iter()
        .any(|name| renderer.contains(name))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn launch_command(exe: &Path, data: &Path) -> Result<String, &'static str> {
    let exe = exe.to_str().ok_or(
        "The executable path is not UTF-8; set --graphics-driver d3d12 in your existing launcher",
    )?;
    let data = data.to_str().ok_or(
        "The data path is not UTF-8; set --graphics-driver d3d12 in your existing launcher",
    )?;
    Ok(format!(
        "{} --graphics-driver d3d12 --data-dir {}",
        shell_quote(exe),
        shell_quote(data)
    ))
}

pub(crate) fn repaint_delay(active: bool) -> Duration {
    if active {
        Duration::from_millis(50)
    } else {
        Duration::from_secs(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn measurements_are_bounded_and_renderer_is_not_guessed_from_vendor() {
        let mut perf = Performance::default();
        for _ in 0..1000 {
            perf.record(Duration::from_micros(250));
        }
        assert_eq!(perf.samples.len(), SAMPLE_LIMIT);
        assert!(software_renderer("llvmpipe (LLVM 19)"));
        assert!(!software_renderer("D3D12 (AMD Radeon Graphics)"));
        assert!(!software_renderer(""));
        assert_eq!(repaint_delay(true), Duration::from_millis(50));
        assert_eq!(repaint_delay(false), Duration::from_secs(1));
    }
    fn feed(perf: &mut Performance, now: Instant, ago_ms: &[u64], ui_us: u64) {
        for ms in ago_ms {
            perf.record_at(
                now - Duration::from_millis(*ms),
                Duration::from_micros(ui_us),
            );
        }
    }
    #[test]
    fn frame_rate_is_measured_over_the_last_second_only() {
        let now = Instant::now();
        let mut perf = Performance::default();
        // Old frames, then a steady 100 fps burst ending now.
        feed(&mut perf, now, &[5000, 4000, 3000], 100);
        let burst: Vec<u64> = (0..=50).rev().map(|i| i * 10).collect();
        feed(&mut perf, now, &burst, 400);
        let rate = perf.frame_rate(now).expect("busy");
        assert!((rate.fps - 100.0).abs() < 0.5, "{rate:?}");
        assert!((rate.frame_ms - 10.0).abs() < 0.1, "{rate:?}");
        assert!((rate.ui_ms - 0.4).abs() < 0.01, "{rate:?}");
        assert!(rate.text().starts_with("100 fps"));
    }
    #[test]
    fn an_idle_window_reports_idle_and_remembers_the_last_rate() {
        let now = Instant::now();
        let mut perf = Performance::default();
        assert_eq!(perf.fps_label(now), ("idle".to_owned(), false));
        feed(&mut perf, now, &[60, 40, 20, 0], 100);
        let (busy, live) = perf.fps_label(now);
        assert!(live && busy.starts_with("50 fps"), "{busy}");
        // A frame per second (the app's idle cadence) is idle, not a rate.
        let later = now + Duration::from_millis(1500);
        let (idle, live) = perf.fps_label(later);
        assert!(!live && idle == "idle \u{b7} last 50 fps", "{idle}");
        perf.record_at(later, Duration::from_micros(100));
        assert!(!perf.fps_label(later).1);
    }
    #[test]
    fn remembered_frames_stay_bounded() {
        let now = Instant::now();
        let mut perf = Performance::default();
        for _ in 0..5000 {
            perf.record_at(now, Duration::from_micros(10));
        }
        assert!(perf.frames.len() <= FRAME_LIMIT);
        // Zero elapsed time between frames is not a rate.
        assert!(perf.frame_rate(now).is_none());
    }
    #[test]
    fn copied_paths_preserve_shell_metacharacters_literally() {
        assert_eq!(shell_quote("a'b;$(x)"), "'a'\"'\"'b;$(x)'");
        use std::os::unix::ffi::OsStrExt;
        assert!(launch_command(
            Path::new("/app"),
            Path::new(std::ffi::OsStr::from_bytes(b"/bad\xff"))
        )
        .is_err());
    }
}
