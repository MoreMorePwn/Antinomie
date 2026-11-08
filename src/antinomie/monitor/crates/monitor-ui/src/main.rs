// SPDX-License-Identifier: GPL-3.0-only
mod activity;
mod analysis;
mod api_keys_window;
mod app;
mod archive;
mod background;
mod branding;
mod build_wizard;
mod code_listing;
mod content_view;
mod core_budget;
mod core_view;
mod data_view;
mod dependencies_window;
mod details_scroll;
mod disk_view;
mod evidence;
mod evidence_delete;
mod evidence_jobs;
mod export_dirs;
mod folders;
mod getting_started;
mod hex_view;
mod jobs;
#[cfg(test)]
mod memory_probe;
mod memory_view;
mod mermaid;
mod network_view;
mod query;
mod reduced_text;
mod regex_matches;
mod route_ui;
mod rules_window;
mod run_filter;
mod run_link;
mod run_recording;
mod run_state_line;
mod runs;
mod sample_tags;
mod samples_view;
mod settings_link;
mod snapshots;
mod stat_cache;
mod summary;
mod table_sort;
mod terminal;
mod theme;
mod title_bar;
mod toasts;
mod tools_page;
mod trace;
mod tree_lines;
mod triage;
mod typing;
mod ui_performance;
mod update_window;
mod vm_screen;
mod widgets;
mod workspace;

pub(crate) use antinomie_triage::{bpf, time_format, tzone, values};

use antinomie_monitor_core::BackendOptions;
use clap::Parser;
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "antinomie",
    version = antinomie_monitor_core::api::APP_BUILD,
    about = "Native Antinomie VM and syscall monitor"
)]
struct Arguments {
    /// Explicit per-launch Mesa driver selection (D3D12 is intended for WSLg).
    #[arg(long, value_enum, default_value = "system")]
    graphics_driver: GraphicsDriver,
    #[arg(long)]
    bundle: Option<PathBuf>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, value_parser = hexadecimal)]
    bootstrap_gpa: Option<u64>,
    #[arg(long)]
    tcg: bool,
    #[arg(long)]
    smoke_exit: bool,
    /// Check runtime requirements without opening the UI or modifying app data.
    #[arg(long)]
    check_dependencies: bool,
    /// Import a verified boot bundle into the durable base catalog without opening the UI.
    #[arg(long)]
    install_base: Option<PathBuf>,
}

#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum GraphicsDriver {
    System,
    D3d12,
}

#[cfg(test)]
mod graphics_option_tests {
    use super::*;
    /// A swap that waits for a compositor frame callback never returns for a
    /// window the compositor is not showing; with detached windows drawn from
    /// the main window's update that stops every window.
    #[test]
    fn buffer_swaps_never_wait_for_the_compositor() {
        assert!(!native_options().glow_options.vsync);
    }

    #[test]
    fn driver_selection_is_explicit_and_unknown_drivers_are_rejected() {
        assert!(
            Arguments::try_parse_from(["antinomie"])
                .unwrap()
                .graphics_driver
                == GraphicsDriver::System
        );
        assert!(
            Arguments::try_parse_from(["antinomie", "--graphics-driver", "d3d12"])
                .unwrap()
                .graphics_driver
                == GraphicsDriver::D3d12
        );
        assert!(Arguments::try_parse_from(["antinomie", "--graphics-driver", "unknown"]).is_err());
    }
}

/// An absolute, canonical data directory. Helpers (Sigma's interpreter, the
/// capa and IDS workers) are started from other working directories, so a
/// relative path would resolve to something else there.
fn absolute_data_dir(path: &std::path::Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

#[cfg(test)]
mod data_dir_tests {
    use super::*;

    #[test]
    fn a_relative_data_dir_becomes_absolute() {
        let relative = absolute_data_dir(std::path::Path::new("data/not-yet-created"));
        assert!(relative.is_absolute());
        assert!(relative.ends_with("data/not-yet-created"));
        let dot = absolute_data_dir(std::path::Path::new("."));
        assert!(dot.is_absolute());
        assert!(!dot.ends_with("."));
    }
}

fn hexadecimal(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
}

fn main() -> eframe::Result<()> {
    if let Some(code) = antinomie_monitor_core::analysis::detection::worker_main_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = antinomie_monitor_core::analysis::properties::worker_main_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = antinomie_monitor_core::disks::reader::worker_main_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = antinomie_triage::copier::host_copier() {
        std::process::exit(code);
    }
    let args = Arguments::parse();
    // Before eframe or background workers start; changes only this process.
    if args.graphics_driver == GraphicsDriver::D3d12 {
        // SAFETY: Nothing else is running yet. No thread has been started, so
        // no other thread can read or write the environment.
        unsafe { std::env::set_var("GALLIUM_DRIVER", "d3d12") };
    }
    let restore_bundle = args.bundle.is_none();
    let mut options = BackendOptions::default();
    if let Some(bundle) = args.bundle {
        options.bundle_dir = bundle;
    }
    if let Some(data_dir) = args.data_dir {
        options.data_dir = absolute_data_dir(&data_dir);
    }
    options.bootstrap_gpa = args.bootstrap_gpa;
    options.force_tcg = args.tcg;
    options.reduced_keep_calls = triage::watched_calls();
    triage::register_live_judge();
    if args.check_dependencies {
        let report = antinomie_monitor_core::dependencies::check(&options);
        for check in &report.checks {
            match &check.problem {
                Some(problem) if check.is_warning() => {
                    println!("Warning: {}: {problem}. {}", check.name, check.hint)
                }
                Some(problem) => println!("{}: {problem}. {}", check.name, check.hint),
                None => println!("{}: ready", check.name),
            }
        }
        if !options.force_tcg && !report.warnings().is_empty() {
            eprintln!(
                "Warning: KVM is not available; VMs run with TCG software emulation, much slower (roughly 10 to 50 times). Use --tcg or set a VM to TCG to silence this."
            );
        }
        if report.has_missing() {
            eprintln!("{}", failure_line("some runtime requirements are missing"));
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    if let Some(directory) = args.install_base {
        // A plain message and exit code 1, not eframe's Debug form of the error.
        match antinomie_monitor_core::direct::install_base(options, directory) {
            Ok(message) => println!("{message}"),
            Err(message) => {
                eprintln!("{}", failure_line(&message));
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    let smoke = args.smoke_exit.then_some(Duration::from_secs(3));
    eframe::run_native(
        "Antinomie Monitor",
        native_options(),
        Box::new(move |cc| {
            Ok(Box::new(app::MonitorApp::new(
                cc,
                options,
                smoke,
                restore_bundle,
            )))
        }),
    )
}

/// Window options for the app and its detached windows.
fn native_options() -> eframe::NativeOptions {
    // The embedded icon also works when the application is run from source.
    let mut viewport = title_bar::builder(eframe::egui::ViewportBuilder::default())
        .with_app_id("antinomie")
        .with_title(format!("Antinomie {}", antinomie_monitor_core::APP_VERSION))
        .with_inner_size([1280.0, 820.0])
        .with_min_inner_size([800.0, 600.0])
        .with_drag_and_drop(true);
    if let Some(icon) = branding::window_icon() {
        viewport = viewport.with_icon(icon);
    }
    eframe::NativeOptions {
        // Matches the desktop entry (assets/antinomie.desktop) so the menu
        // icon applies to the running window.
        viewport,
        // Detached windows are drawn from the main window's update on the one
        // UI thread. With vsync every buffer swap waits for the compositor's
        // next frame callback, and a compositor sends none to a window it is
        // not showing (idle, covered or minimized on WSLg's Wayland): the swap
        // of that one window then never returns and every window stops
        // answering. Without vsync a swap never waits.
        glow_options: eframe::egui_glow::GlowConfiguration {
            vsync: ui_performance::VSYNC,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The one line a failed command-line action prints on standard error.
fn failure_line(message: &str) -> String {
    format!("Error: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_failures_are_plain_text() {
        assert_eq!(failure_line("no bundle"), "Error: no bundle");
    }
}
