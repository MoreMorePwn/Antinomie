mod app;
mod terminal;

use antinomie_monitor_core::BackendOptions;
use clap::Parser;
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(version, about = "Native Antinomie VM and syscall monitor")]
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
}

fn hexadecimal(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).map_err(|error| error.to_string())
}

fn main() -> eframe::Result<()> {
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
    let smoke = args.smoke_exit.then_some(Duration::from_secs(3));
    eframe::run_native(
        "Antinomie",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
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
