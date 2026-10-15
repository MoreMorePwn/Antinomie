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
        if self.samples.len() == SAMPLE_LIMIT {
            self.samples.pop_front();
        }
        self.samples.push_back(elapsed.as_secs_f64() * 1000.0);
        let now = Instant::now();
        self.interval_ms = self
            .last_frame
            .map(|last| now.duration_since(last).as_secs_f64() * 1000.0);
        self.last_frame = Some(now);
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
                    ui.add(egui::Label::new(egui::RichText::new("Software rendering uses the CPU and can slow the whole window.").color(theme::warn())).wrap());
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
                if let Some(error) = &self.error { ui.colored_label(theme::error(), error); }
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
