// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Manual check of static analysis of a host file (the Disks tab's "Hand to
//! Static Analysis"), with no VM: queue the file through the backend and wait
//! for its report. The worker is this program, as the app's workers are.
//!
//! usage: host-analysis-check NEW_DATA_DIR FILE
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
                checks: AnalysisKind::TRIAGE.to_vec(),
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
            if let Some(report) = snapshot.analysis_reports.iter().find(|report| {
                !matches!(
                    report.state,
                    AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
                )
            }) {
                println!("state {:?}, reason {:?}", report.state, report.reason);
                for section in &report.sections {
                    println!(
                        "  {:?}: {:?} ({})",
                        section.kind, section.state, section.summary
                    );
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
