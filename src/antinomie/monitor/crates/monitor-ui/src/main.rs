mod analysis;
mod app;
mod archive;
mod bpf;
mod build_wizard;
mod core_view;
mod data_view;
mod dependencies_window;
mod evidence;
mod evidence_jobs;
mod folders;
mod memory_view;
mod network_view;
mod query;
mod run_filter;
mod runs;
mod samples_view;
mod snapshots;
mod summary;
mod terminal;
mod theme;
mod time_format;
mod tools_window;
mod trace;
mod triage;
mod ui_performance;
mod values;
mod workspace;

use antinomie_monitor_core::{Backend, BackendOptions, Command, Notification};
use clap::Parser;
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "antinomie",
    version,
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
    if let Some(code) = antinomie_monitor_core::analysis::properties::worker_main_if_requested() {
        std::process::exit(code);
    }
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args = Arguments::parse();
    // Before eframe or background workers start; changes only this process.
    if args.graphics_driver == GraphicsDriver::D3d12 {
        std::env::set_var("GALLIUM_DRIVER", "d3d12");
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
    if args.check_dependencies {
        let report = antinomie_monitor_core::dependencies::check(&options);
        for check in &report.checks {
            match &check.problem {
                Some(problem) => println!("{}: {problem}. {}", check.name, check.hint),
                None => println!("{}: ready", check.name),
            }
        }
        std::process::exit(i32::from(report.has_missing()));
    }
    if let Some(directory) = args.install_base {
        return install_base(options, directory).map_err(|message| {
            eframe::Error::AppCreation(Box::new(std::io::Error::other(message)))
        });
    }
    let smoke = args.smoke_exit.then_some(Duration::from_secs(3));
    eframe::run_native(
        "Antinomie Monitor",
        eframe::NativeOptions {
            // Matches the desktop entry (assets/antinomie.desktop) so the menu
            // icon applies to the running window.
            viewport: eframe::egui::ViewportBuilder::default()
                .with_app_id("antinomie")
                .with_title(format!("Antinomie {}", antinomie_monitor_core::APP_VERSION))
                .with_inner_size([1280.0, 820.0])
                .with_min_inner_size([800.0, 600.0]),
            ..Default::default()
        },
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
