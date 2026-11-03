// SPDX-License-Identifier: GPL-3.0-only
mod activity;
mod analysis;
mod api_keys_window;
mod app;
mod archive;
mod background;
mod bpf;
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
mod folders;
mod getting_started;
mod hex_view;
mod jobs;
#[cfg(test)]
mod memory_probe;
mod memory_view;
mod network_view;
mod query;
mod reduced_text;
mod regex_matches;
mod route_ui;
mod rules_window;
mod run_filter;
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
mod time_format;
mod title_bar;
mod toasts;
mod tools_page;
mod trace;
mod tree_lines;
mod triage;
mod typing;
mod ui_performance;
mod update_window;
mod values;
mod widgets;
mod workspace;

use antinomie_monitor_core::{Backend, BackendOptions, Command, Notification};
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
    if let Some(code) = antinomie_monitor_core::file_before_store::worker_main_if_requested(
        triage::copy_earlier_bytes,
    ) {
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
        options.data_dir = data_dir;
    }
    options.bootstrap_gpa = args.bootstrap_gpa;
    options.force_tcg = args.tcg;
    options.reduced_keep_calls = triage::watched_calls();
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
        if let Err(message) = install_base(options, directory) {
            eprintln!("{}", failure_line(&message));
            std::process::exit(1);
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

fn install_base(options: BackendOptions, directory: PathBuf) -> Result<(), String> {
    let mut backend = Backend::new(options)?;
    let id = backend.send(Command::ImportBase { directory })?;
    // Copying and verifying a desktop image can exceed two minutes. The worker
    // owns that operation until completion, including during shutdown, so a
    // frontend deadline cannot cancel it or truthfully report its outcome.
    let result = wait_for_base_import(id, |timeout| backend.recv_timeout(timeout));
    let shutdown = backend.shutdown();
    match (result, shutdown) {
        (Ok(message), Ok(())) => {
            println!("{message}");
            Ok(())
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(shutdown)) => Err(format!("{error}; shutdown: {shutdown}")),
    }
}

fn wait_for_base_import(
    id: u64,
    mut receive: impl FnMut(Duration) -> Result<Option<Notification>, String>,
) -> Result<String, String> {
    loop {
        if let Some(Notification::CommandResult {
            id: reply,
            success,
            message,
        }) = receive(Duration::from_secs(1))?
        {
            if reply == id {
                return if success { Ok(message) } else { Err(message) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_failures_are_plain_text() {
        assert_eq!(failure_line("no bundle"), "Error: no bundle");
    }

    #[test]
    fn base_import_waits_past_two_minutes_of_receive_timeouts_for_its_result() {
        let mut polls = 0;
        let result = wait_for_base_import(7, |timeout| {
            assert_eq!(timeout, Duration::from_secs(1));
            polls += 1;
            Ok((polls > 130).then(|| Notification::CommandResult {
                id: 7,
                success: true,
                message: "base imported".into(),
            }))
        });
        assert_eq!(result.as_deref(), Ok("base imported"));
        assert_eq!(polls, 131);
    }

    #[test]
    fn base_import_ignores_other_commands_and_preserves_its_failure() {
        let mut notifications = [
            Notification::CommandResult {
                id: 6,
                success: true,
                message: "another command completed".into(),
            },
            Notification::CommandResult {
                id: 7,
                success: false,
                message: "bundle changed during import; copies rejected".into(),
            },
        ]
        .into_iter();
        let result = wait_for_base_import(7, |_| Ok(notifications.next()));
        assert_eq!(
            result,
            Err("bundle changed during import; copies rejected".into())
        );
    }

    #[test]
    fn base_import_reports_disconnected_worker_without_claiming_success() {
        let result = wait_for_base_import(7, |_| Err("backend owner disconnected".into()));
        assert_eq!(result, Err("backend owner disconnected".into()));
    }
}
