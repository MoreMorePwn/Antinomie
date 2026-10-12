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
mod runs;
mod samples_view;
mod snapshots;
mod summary;
mod terminal;
mod theme;
mod tools_window;
mod trace;
mod triage;
mod values;
mod workspace;

use antinomie_monitor_core::{Backend, BackendOptions, Command, Notification};
use clap::Parser;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "antinomie",
    version,
    about = "Native Antinomie VM and syscall monitor"
)]
struct Arguments {
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

fn hexadecimal(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
}

fn main() -> eframe::Result<()> {
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args = Arguments::parse();
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
    let deadline = Instant::now() + Duration::from_secs(120);
    let result = loop {
        if let Some(Notification::CommandResult {
            id: reply,
            success,
            message,
        }) = backend.try_recv()
        {
            if reply == id {
                break if success {
                    println!("{message}");
                    Ok(())
                } else {
                    Err(message)
                };
            }
        }
        if Instant::now() >= deadline {
            break Err("base import timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    backend.shutdown()?;
    result
}
