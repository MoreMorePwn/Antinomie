// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Manual check of static analysis of a host file (the Disks tab's "Hand to
//! Static Analysis"), with no VM: queue the file through the backend and wait
//! for its report. The worker is this program, as the app's workers are.
//!
//! usage: host-analysis-check NEW_DATA_DIR FILE
//!
//! The environment can widen the check: `ANTINOMIE_CHECK_KINDS` is a comma
//! separated list of categories to add (`floss`) and
//! `ANTINOMIE_CHECK_TOOLS` a folder of unpacked tools (`floss/floss`) that is
//! copied to `<data dir>/tools`, so a tool needs no download.
use antinomie_monitor_core::{
    AnalysisKind, AnalysisSectionState, AnalysisSelection, AnalysisState, Backend, BackendOptions,
    Command, Notification, Snapshot,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

fn main() {
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| -> Result<(), String> {
        if args.len() != 2 {
            return Err("usage: host-analysis-check NEW_DATA_DIR FILE".into());
        }
        let data_dir = PathBuf::from(&args[0]);
        if data_dir.exists() {
            return Err("the data directory must not already exist".into());
        }
        let file = PathBuf::from(&args[1]);
        let expected = format!(
            "{:x}",
            Sha256::digest(fs::read(&file).map_err(|e| e.to_string())?)
        );
        let mut checks = AnalysisKind::TRIAGE.to_vec();
        for name in std::env::var("ANTINOMIE_CHECK_KINDS")
            .unwrap_or_default()
            .split(',')
            .filter(|name| !name.is_empty())
        {
            checks.push(match name {
                "floss" => AnalysisKind::Floss,
                other => return Err(format!("unknown check {other}")),
            });
        }
        if let Some(tools) = std::env::var_os("ANTINOMIE_CHECK_TOOLS") {
            let target = data_dir.join("tools");
            fs::create_dir_all(&target).map_err(|e| e.to_string())?;
            let status = std::process::Command::new("cp")
                .arg("-a")
                .arg("--")
                .arg(PathBuf::from(&tools).join("."))
                .arg(&target)
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err("cannot copy the tools".into());
            }
        }
        let mut backend = Backend::new(BackendOptions {
            data_dir,
            ..BackendOptions::default()
        })?;
        let mut snapshot = Snapshot::default();
        let id = backend.send(Command::AnalyzeHostFile {
            vm_id: "qa".into(),
            path: file,
            analysis: AnalysisSelection {
                enabled: true,
                checks,
                time_limit_minutes: 0,
            },
        })?;
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut accepted = false;
        loop {
            while let Some(notification) = backend.try_recv() {
                match notification {
                    Notification::Snapshot(next) => snapshot = next,
                    Notification::CommandResult {
                        id: result,
                        success,
                        message,
                    } if result == id => {
                        if !success {
                            return Err(message);
                        }
                        accepted = true;
                    }
                    _ => {}
                }
            }
            let finished = |report: &&antinomie_monitor_core::AnalysisReport| {
                !matches!(
                    report.state,
                    AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
                )
            };
            if let Some(report) = snapshot
                .analysis_reports
                .iter()
                .filter(|report| report.layer.is_none())
                .find(finished)
            {
                // A packed file's unpacked layers are analysed after it; wait for them.
                let wanted = antinomie_monitor_core::unpack_layers(report)
                    .iter()
                    .filter(|layer| layer.index > 0)
                    .count();
                let layers: Vec<_> = snapshot
                    .analysis_reports
                    .iter()
                    .filter(|other| other.layer.is_some())
                    .filter(finished)
                    .collect();
                if layers.len() < wanted && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                println!("state {:?}, reason {:?}", report.state, report.reason);
                for section in &report.sections {
                    println!(
                        "  {:?}: {:?} ({})",
                        section.kind, section.state, section.summary
                    );
                }
                for layer in antinomie_monitor_core::unpack_layers(report) {
                    println!(
                        "  layer {}: {} {} {} bytes, packer {:?}, analysis {:?}",
                        layer.index,
                        layer.method,
                        layer.sha256,
                        layer.size,
                        layer.packer,
                        layer.report_id
                    );
                }
                for other in &layers {
                    println!(
                        "  layer report {} {:?} of {:?}: {}",
                        other.id,
                        other.state,
                        other.layer.as_ref().map(|layer| layer.index),
                        other
                            .sections
                            .iter()
                            .map(|section| format!("{:?}={:?}", section.kind, section.state))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                }
                if layers.len() < wanted {
                    return Err(format!(
                        "only {} of {wanted} layer analyses finished",
                        layers.len()
                    ));
                }
                // Partial: optional tools (capa, rules) are not installed here.
                if !matches!(
                    report.state,
                    AnalysisState::Complete | AnalysisState::Partial
                ) {
                    return Err(format!("analysis ended {:?}", report.state));
                }
                if !report
                    .sections
                    .iter()
                    .any(|section| section.state == AnalysisSectionState::Complete)
                {
                    return Err("no analysis section completed".into());
                }
                if report.specimen_sha256.as_deref() != Some(&expected) {
                    return Err("the report names another specimen".into());
                }
                if !accepted {
                    return Err("no command result".into());
                }
                println!("PASS specimen {expected}");
                break;
            }
            if Instant::now() >= deadline {
                return Err("deadline".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        backend.shutdown()
    })();
    if let Err(error) = result {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
