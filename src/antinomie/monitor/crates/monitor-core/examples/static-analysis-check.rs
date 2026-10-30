// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
use antinomie_monitor_core::{
    AnalysisKind, AnalysisReport, AnalysisSelection, AnalysisState, Backend, BackendOptions,
    Command, ExecRequest, Notification, RunSummary, Snapshot, VmConfig,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

struct Harness {
    backend: Backend,
    snapshot: Snapshot,
    results: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, Vec<u8>>,
}

impl Harness {
    fn receive(&mut self) -> Result<(), String> {
        while let Some(notification) = self.backend.try_recv() {
            match notification {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::RunStarted(run) => {
                    if !self.snapshot.runs.iter().any(|old| old.id == run.id) {
                        self.snapshot.runs.push(run);
                    }
                }
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.results
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { run_id, data, .. } => {
                    let output = self.output.entry(run_id).or_default();
                    if output.len() + data.len() > 1024 * 1024 {
                        return Err("test terminal output exceeded 1 MiB".into());
                    }
                    output.extend(data);
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn wait(
        &mut self,
        seconds: u64,
        mut predicate: impl FnMut(&Self) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive()?;
            if predicate(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "test deadline; state {:?}, error {:?}",
                    self.snapshot.state, self.snapshot.last_error
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        let id = self.backend.send(command)?;
        self.wait(60, |test| test.results.contains_key(&id))?;
        self.results.remove(&id).ok_or("missing command result")??;
        Ok(())
    }

    fn launch(
        &mut self,
        path: &str,
        args: Vec<String>,
        enabled: bool,
        uid: u32,
    ) -> Result<String, String> {
        let before = self.snapshot.runs.len();
        self.command(Command::Execute(ExecRequest {
            path: path.into(),
            args,
            uid,
            gid: uid,
            analysis: selection(enabled),
            ..ExecRequest::default()
        }))?;
        self.wait(10, |test| test.snapshot.runs.len() > before)?;
        Ok(self
            .snapshot
            .runs
            .last()
            .ok_or("missing new run")?
            .id
            .clone())
    }

    fn run(&self, id: &str) -> Option<&RunSummary> {
        self.snapshot.runs.iter().find(|run| run.id == id)
    }

    fn report(&mut self, id: &str) -> Result<AnalysisReport, String> {
        self.wait(150, |test| {
            test.run(id)
                .and_then(|run| run.analysis.as_ref())
                .is_some_and(|report| {
                    matches!(
                        report.state,
                        AnalysisState::Complete
                            | AnalysisState::Partial
                            | AnalysisState::Unavailable
                            | AnalysisState::Cancelled
                    )
                })
        })?;
        self.run(id)
            .and_then(|run| run.analysis.clone())
            .ok_or("missing analysis report".into())
    }

    fn terminal(&mut self, id: &str, marker: &str) -> Result<(), String> {
        self.wait(20, |test| {
            test.output.get(id).is_some_and(|data| {
                data.windows(marker.len())
                    .any(|part| part == marker.as_bytes())
            })
        })
    }
}

fn selection(enabled: bool) -> AnalysisSelection {
    AnalysisSelection {
        enabled,
        checks: vec![
            AnalysisKind::Metadata,
            AnalysisKind::Structures,
            AnalysisKind::Strings,
            AnalysisKind::Entropy,
            AnalysisKind::Hardening,
            AnalysisKind::Disassembly,
        ],
        time_limit_minutes: 0,
    }
}

fn exercise(
    test: &mut Harness,
    root: &std::path::Path,
    probe: &std::path::Path,
) -> Result<(), String> {
    test.command(Command::Create(VmConfig {
        name: "Static analysis QA".into(),
        cpus: 4,
        ram_mib: 1024,
        disk_gib: 1,
        ..VmConfig::default()
    }))?;
    test.wait(10, |test| !test.snapshot.vms.is_empty())?;
    test.command(Command::Start {
        vm_id: test.snapshot.vms[0].id.clone(),
    })?;
    test.wait(60, |test| {
        test.snapshot
            .serial_log
            .as_ref()
            .and_then(|path| fs::read(path).ok())
            .is_some_and(|data| {
                data.windows(b"BusyBox guest ready".len())
                    .any(|part| part == b"BusyBox guest ready")
            })
    })?;
    for (source, destination, executable) in [
        (probe.to_path_buf(), "/tmp/static-probe", true),
        (
            root.join("initial-script.sh"),
            "/tmp/static-script.sh",
            true,
        ),
        (root.join("unknown.bin"), "/tmp/static-unknown.bin", false),
    ] {
        test.command(Command::Upload {
            source,
            destination: destination.into(),
            overwrite: false,
            executable,
        })?;
    }
    let setup = test.launch("/bin/sh", vec!["-c".into(),
        "cp /tmp/static-probe /tmp/static-execute-only; chmod 111 /tmp/static-execute-only; chmod 644 /tmp/static-unknown.bin; echo SETUP-OK".into()], false, 0)?;
    test.terminal(&setup, "SETUP-OK")?;
    let off = test.launch("/tmp/static-probe", vec!["OFF".into()], false, 1000)?;
    test.terminal(&off, "marker=OFF")?;
    if test.run(&off).is_some_and(|run| run.analysis.is_some()) {
        return Err("disabled analysis generated a report".into());
    }
    let on = test.launch("/tmp/static-probe", vec!["ON".into()], true, 1000)?;
    test.terminal(&on, "marker=ON")?;
    let mut queued = Vec::new();
    for marker in ["QUEUED-A", "QUEUED-B"] {
        queued.push(test.launch("/tmp/static-probe", vec![marker.into()], true, 1000)?);
    }
    let report = test.report(&on)?;
    let expected = format!(
        "{:x}",
        Sha256::digest(fs::read(probe).map_err(|e| e.to_string())?)
    );
    if report.specimen_sha256.as_deref() != Some(&expected) {
        return Err(format!("initial ELF SHA-256 mismatch: {report:?}"));
    }
    if !matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    ) {
        return Err(format!("ELF analyzer unavailable: {report:?}"));
    }
    for id in &queued {
        let queued_report = test.report(id)?;
        if queued_report.specimen_sha256.as_deref() != Some(expected.as_str())
            || !matches!(
                queued_report.state,
                AnalysisState::Complete | AnalysisState::Partial
            )
        {
            return Err(format!(
                "queued specimen was not preserved: {queued_report:?}"
            ));
        }
    }
    println!("PASS three queued launch specimens retain the original ELF hash");
    println!(
        "PASS initial ELF capture and analyzer: {}",
        serde_json::to_string(&report).map_err(|e| e.to_string())?
    );
    let script = test.launch("/tmp/static-script.sh", vec![], true, 1000)?;
    test.terminal(&script, "SCRIPT-OK")?;
    let script_report = test.report(&script)?;
    let script_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(root.join("initial-script.sh")).map_err(|e| e.to_string())?)
    );
    if script_report.specimen_sha256.as_deref() != Some(&script_hash) {
        return Err("captured interpreter instead of initially opened script".into());
    }
    let unreadable = test.launch(
        "/tmp/static-execute-only",
        vec!["UNREADABLE".into()],
        true,
        1000,
    )?;
    test.terminal(&unreadable, "marker=UNREADABLE")?;
    if test.report(&unreadable)?.state != AnalysisState::Unavailable {
        return Err("execute-only file exported without read permission".into());
    }
    println!("PASS disabled no report, script identity, unreadable fail-open, separate terminal");
    let run_count = test.snapshot.runs.len();
    test.command(Command::AnalyzeOnly {
        path: "/tmp/static-unknown.bin".into(),
        uid: 1000,
        gid: 1000,
        analysis: AnalysisSelection {
            enabled: true,
            checks: vec![
                AnalysisKind::Metadata,
                AnalysisKind::Strings,
                AnalysisKind::Entropy,
            ],
            time_limit_minutes: 0,
        },
    })?;
    test.wait(60, |test| {
        test.snapshot.analysis_reports.iter().any(|report| {
            report.source_path == "/tmp/static-unknown.bin"
                && matches!(
                    report.state,
                    AnalysisState::Complete | AnalysisState::Partial | AnalysisState::Unavailable
                )
        })
    })?;
    let standalone = test
        .snapshot
        .analysis_reports
        .iter()
        .find(|report| report.source_path == "/tmp/static-unknown.bin")
        .ok_or("missing standalone report")?;
    let generic_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(root.join("unknown.bin")).map_err(|e| e.to_string())?)
    );
    if standalone.specimen_sha256.as_deref() != Some(&generic_hash)
        || test.snapshot.runs.len() != run_count
    {
        return Err(
            "Analyze Only changed execution history or failed generic byte identity".into(),
        );
    }
    let cancelled = test.launch("/tmp/static-probe", vec!["CANCEL".into()], true, 1000)?;
    let analysis_id = test
        .run(&cancelled)
        .and_then(|run| run.analysis.as_ref())
        .ok_or("missing cancellable job")?
        .id
        .clone();
    test.command(Command::CancelAnalysis { analysis_id })?;
    test.terminal(&cancelled, "marker=CANCEL")?;
    if test.report(&cancelled)?.state != AnalysisState::Cancelled {
        return Err("cancelled analysis did not retain cancellation state".into());
    }
    println!(
        "PASS Analyze Only generic hash without execution; cancellation leaves program running"
    );
    if !test.snapshot.events.iter().any(|event| {
        event.root_task_cookie == test.run(&on).map(|r| r.root_task_cookie).unwrap_or(0)
    }) {
        return Err("no syscall telemetry during analyzed execution".into());
    }
    test.command(Command::Stop)?;
    let run_dir = test
        .run(&on)
        .ok_or("run missing after stop")?
        .directory
        .clone();
    let persisted: RunSummary =
        serde_json::from_slice(&fs::read(run_dir.join("run.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if persisted
        .analysis
        .as_ref()
        .and_then(|report| report.specimen_sha256.as_deref())
        != Some(&expected)
    {
        return Err("final run archive did not retain analysis identity".into());
    }
    let reopened = antinomie_monitor_core::analysis::open_report(&run_dir.join("analysis"))?;
    if reopened.specimen_sha256.as_deref() != Some(&expected) {
        return Err("analysis sidecar reopen changed specimen identity".into());
    }
    println!(
        "PASS four-core telemetry and persisted report; run {}",
        run_dir.display()
    );
    Ok(())
}

fn main() {
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = (|| -> Result<(), String> {
        if args.len() != 3 {
            return Err("usage: static-analysis-check BUNDLE NEW_QA_DIR STATIC_PROBE_ELF".into());
        }
        let root = PathBuf::from(&args[1]);
        if root.exists() {
            return Err("QA directory must not already exist".into());
        }
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        fs::write(
            root.join("initial-script.sh"),
            b"#!/bin/sh\necho SCRIPT-OK\n",
        )
        .map_err(|e| e.to_string())?;
        fs::write(
            root.join("unknown.bin"),
            b"unknown specimen\0ANTINOMIE-GENERIC-STRING\n",
        )
        .map_err(|e| e.to_string())?;
        let mut test = Harness {
            backend: Backend::new(BackendOptions {
                data_dir: root.join("data"),
                bundle_dir: PathBuf::from(&args[0]),
                headless: true,
                force_tcg: true,
                // Three concurrent jobs reserve bounded listing/scratch space
                // before acquisition; the retained test evidence stays small.
                capture_quota_size: 1024 * 1024 * 1024,
                ..BackendOptions::default()
            })?,
            snapshot: Snapshot::default(),
            results: BTreeMap::new(),
            output: BTreeMap::new(),
        };
        let result = exercise(&mut test, &root, &PathBuf::from(&args[2]));
        let cleanup = test.backend.shutdown();
        result.and(cleanup)
    })();
    if let Err(error) = result {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
