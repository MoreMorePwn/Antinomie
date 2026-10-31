// SPDX-License-Identifier: GPL-3.0-only
//! Drive one base build through the backend, as the "Build base" wizard does.
//!
//! usage: build-base DATA_DIR busybox|debian-minimal|debian-xfce automatic|native|podman|docker|qemu [OPTIONS_JSON]
//!
//! OPTIONS_JSON overrides fields of the profile's default answers, for example
//! '{"hostname":"lab","timezone":"Europe/Berlin"}'. Prints stage changes and
//! build output, then the installed bases.

use antinomie_monitor_core::{
    Backend, BackendOptions, Command, Notification, Snapshot,
    build::{self, BuildMode, BuildOptions, BuildRequest},
};
use std::{path::PathBuf, process::ExitCode, thread, time::Duration};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("build-base: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(3..=4).contains(&args.len()) {
        return Err(
            "usage: build-base DATA_DIR busybox|debian-minimal|debian-xfce automatic|native|podman|docker|qemu [OPTIONS_JSON]"
                .into(),
        );
    }
    let profile = build::profile(&args[1]).ok_or("unknown profile")?;
    let mode = match args[2].as_str() {
        "automatic" => BuildMode::Automatic,
        "native" => BuildMode::Native,
        "podman" => BuildMode::Podman,
        "docker" => BuildMode::Docker,
        "qemu" => BuildMode::Qemu,
        other => return Err(format!("unknown mode {other}")),
    };
    let mut options =
        serde_json::to_value(BuildOptions::defaults(profile.kind)).map_err(|e| e.to_string())?;
    if let Some(overrides) = args.get(3) {
        let overrides: serde_json::Value =
            serde_json::from_str(overrides).map_err(|e| e.to_string())?;
        for (key, value) in overrides
            .as_object()
            .ok_or("OPTIONS_JSON must be an object")?
        {
            options[key] = value.clone();
        }
    }
    let options: BuildOptions = serde_json::from_value(options).map_err(|e| e.to_string())?;
    let backend = Backend::new(BackendOptions {
        data_dir: PathBuf::from(&args[0]),
        headless: true,
        ..BackendOptions::default()
    })?;
    let id = backend.send(Command::BuildBase {
        request: BuildRequest {
            profile: profile.id.into(),
            mode,
            options,
        },
    })?;
    let (mut stage, mut printed, mut snapshot) = (String::new(), 0usize, Snapshot::default());
    loop {
        while let Some(notification) = backend.try_recv() {
            match notification {
                Notification::Snapshot(next) => snapshot = next,
                Notification::CommandResult {
                    id: result,
                    success,
                    message,
                } if result == id => {
                    println!("{message}");
                    if !success {
                        return Err(message);
                    }
                }
                _ => {}
            }
        }
        if let Some(status) = &snapshot.build {
            if status.stage != stage {
                stage = status.stage.clone();
                println!("== stage {stage} ({:?})", status.mode);
            }
            // The status log is a bounded tail; follow the full log file instead.
            if let Some(text) = status
                .log_path
                .as_ref()
                .and_then(|path| std::fs::read(path).ok())
                && text.len() > printed
            {
                print!("{}", String::from_utf8_lossy(&text[printed..]));
                printed = text.len();
            }
            if status.finished {
                if let Some(path) = &status.log_path {
                    println!("log {}", path.display());
                }
                if let Some(error) = &status.error {
                    return Err(error.clone());
                }
                for base in &snapshot.bases {
                    println!(
                        "installed {} {} revision {:?}",
                        base.id, base.label, base.revision
                    );
                }
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
}
