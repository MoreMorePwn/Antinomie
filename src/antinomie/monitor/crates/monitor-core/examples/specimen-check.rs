// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM check of large static-analysis specimens (contract revision 19).
//!
//!   specimen-check BUNDLE NEW_DATA_DIR SPECIMEN_PROBE
//!
//! SPECIMEN_PROBE is the static `tests/monitor/specimen-probe` program, about
//! 95 MiB: over the 64 MiB an older guest keeps, under the 128 MiB of a
//! revision 19 guest. Two BusyBox VMs boot one after the other:
//!
//! * big (2 GiB of RAM, so a quarter is 512 MiB): the probe is uploaded as a
//!   program and run with static analysis. The whole file reaches the host
//!   (length and SHA-256 equal the probe's), every section ends, and none is
//!   cut short by the specimen's size.
//! * small (320 MiB of RAM, a quarter is 80 MiB): the upload as a program is
//!   refused before anything is sent and says how much RAM is needed. The
//!   same file uploaded as a plain file, made executable in the guest and run
//!   with analysis, runs without it, and the report says why.
//!
//! Every check prints a PASS or FAIL line; the data folder must be new and
//! disposable.
use antinomie_monitor_core::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const PROBE: &str = "/tmp/specimen-probe";

struct Driver {
    backend: Backend,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, String>,
}

impl Driver {
    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { run_id, data, .. } => {
                    self.output
                        .entry(run_id)
                        .or_default()
                        .push_str(&String::from_utf8_lossy(&data));
                }
                _ => {}
            }
        }
    }

    fn command(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if let Some(reply) = self.replies.remove(&id) {
                return reply;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        ready: impl Fn(&Self) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if ready(self) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// A BusyBox VM with `ram_mib` of RAM, booted to the guest's ready line.
    fn boot(&mut self, name: &str, ram_mib: u32) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.vms.iter().map(|v| v.id.clone()).collect();
        self.command(
            Command::Create(VmConfig {
                name: name.into(),
                cpus: 2,
                ram_mib,
                disk_gib: 1,
                ..VmConfig::default()
            }),
            600,
        )?;
        self.wait("VM publication", 10, |d| {
            d.snapshot.vms.iter().any(|v| !known.contains(&v.id))
        })?;
        let vm_id = self
            .snapshot
            .vms
            .iter()
            .find(|v| !known.contains(&v.id))
            .ok_or("new VM missing")?
            .id
            .clone();
        self.command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            900,
        )?;
        self.wait("guest", 240, |d| {
            d.snapshot
                .serial_log
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
        })?;
        Ok(vm_id)
    }

    fn upload(&mut self, source: &Path, executable: bool) -> Result<String, String> {
        self.command(
            Command::Upload {
                source: source.to_path_buf(),
                destination: PROBE.into(),
                overwrite: true,
                executable,
            },
            600,
        )
    }

    /// Runs `path` with `args`, with static analysis when `analysis`, and
    /// waits for its end and for its report to settle.
    fn run(&mut self, path: &str, args: &[&str], analysis: bool) -> Result<RunSummary, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        self.command(
            Command::Execute(ExecRequest {
                path: path.into(),
                args: args.iter().map(|a| (*a).to_owned()).collect(),
                uid: 0,
                gid: 0,
                analysis: AnalysisSelection {
                    enabled: analysis,
                    ..AnalysisSelection::default()
                },
                ..Default::default()
            }),
            180,
        )?;
        self.wait("run publication", 15, |d| {
            d.snapshot.runs.iter().any(|r| !known.contains(&r.id))
        })?;
        let id = self
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("new run missing")?
            .id
            .clone();
        let wanted = id.clone();
        self.wait("run end and analysis", 1800, move |d| {
            d.snapshot.runs.iter().any(|r| {
                r.id == wanted
                    && matches!(r.state, RunState::Finished | RunState::Stopped)
                    && r.analysis.as_ref().is_none_or(|report| {
                        !matches!(
                            report.state,
                            AnalysisState::Acquiring
                                | AnalysisState::Queued
                                | AnalysisState::Running
                        )
                    })
            })
        })?;
        self.snapshot
            .runs
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or_else(|| "run vanished".into())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.command(Command::Stop, 120)?;
        self.wait("VM stop", 90, |d| d.snapshot.state == VmState::Stopped)
    }
}

#[derive(Default)]
struct Table {
    failures: Vec<String>,
}

impl Table {
    fn check(&mut self, name: &str, ok: bool, got: impl Into<String>) {
        let got = got.into();
        println!("{} {name}: {got}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            self.failures.push(name.to_owned());
        }
    }
}

fn big(d: &mut Driver, t: &mut Table, probe: &Path, len: u64, sha256: &str) -> Result<(), String> {
    d.boot("specimen check big", 2048)?;
    let uploaded = d.upload(probe, true);
    t.check(
        "big: a 95 MiB program uploads to a 2 GiB VM",
        uploaded.is_ok(),
        format!("{uploaded:?}"),
    );
    uploaded?;
    let run = d.run(PROBE, &["one"], true)?;
    let output = d.output.get(&run.id).cloned().unwrap_or_default();
    t.check(
        "big: the program runs",
        output.contains("SPECIMEN-PROBE"),
        output.trim().to_owned(),
    );
    let Some(report) = run.analysis.as_ref() else {
        t.check("big: the run has an analysis report", false, "none");
        return d.stop();
    };
    t.check(
        "big: the analysis ends",
        matches!(
            report.state,
            AnalysisState::Complete | AnalysisState::Partial
        ),
        format!("{:?} {:?}", report.state, report.reason),
    );
    t.check(
        "big: the whole file reached the host",
        report.specimen_len == Some(len) && report.specimen_sha256.as_deref() == Some(sha256),
        format!("{:?} of {len}", report.specimen_len),
    );
    let sections: Vec<String> = report
        .sections
        .iter()
        .map(|s| format!("{:?}={:?}", s.kind, s.state))
        .collect();
    t.check(
        "big: every section ended",
        report.sections.iter().all(|s| {
            !matches!(
                s.state,
                AnalysisSectionState::Pending | AnalysisSectionState::Running
            )
        }),
        sections.join(" "),
    );
    let sized: Vec<String> = report
        .sections
        .iter()
        .filter(|s| {
            let text = format!("{} {:?}", s.summary, s.limits).to_lowercase();
            text.contains("specimen") && (text.contains("exceed") || text.contains("too large"))
        })
        .map(|s| format!("{:?}: {}", s.kind, s.summary))
        .collect();
    t.check(
        "big: no section is cut short by the specimen's size",
        sized.is_empty(),
        format!("{sized:?}"),
    );
    d.stop()
}

fn small(d: &mut Driver, t: &mut Table, probe: &Path) -> Result<(), String> {
    d.boot("specimen check small", 320)?;
    let refused = d.upload(probe, true);
    let text = refused.as_ref().err().cloned().unwrap_or_default();
    t.check(
        "small: a program over a quarter of the RAM is refused before upload",
        text.contains("quarter of the VM's RAM") && text.contains("at least 512 MiB"),
        text,
    );
    let plain = d.upload(probe, false);
    t.check(
        "small: the same file uploads as a plain file",
        plain.is_ok(),
        format!("{plain:?}"),
    );
    plain?;
    let chmod = d.run("/bin/sh", &["-c", &format!("chmod 755 {PROBE}")], false)?;
    t.check(
        "small: made executable in the guest",
        chmod.state == RunState::Finished,
        format!("{:?}", chmod.state),
    );
    let run = d.run(PROBE, &["two"], true)?;
    let output = d.output.get(&run.id).cloned().unwrap_or_default();
    t.check(
        "small: the program still runs",
        output.contains("SPECIMEN-PROBE"),
        output.trim().to_owned(),
    );
    let reason = run
        .analysis
        .as_ref()
        .and_then(|report| report.reason.clone())
        .unwrap_or_default();
    t.check(
        "small: its analysis says the guest kept no copy, and why",
        run.analysis
            .as_ref()
            .is_some_and(|report| report.state == AnalysisState::Unavailable)
            && reason.contains("larger than the 80.0 MB"),
        reason,
    );
    d.stop()
}

fn check(bundle: &str, data: &str, probe: &str) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the check needs a new disposable data folder".into());
    }
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let probe = PathBuf::from(probe);
    let bytes = fs::read(&probe).map_err(|e| format!("{}: {e}", probe.display()))?;
    let len = bytes.len() as u64;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    drop(bytes);
    if !(64 << 20..128 << 20).contains(&len) {
        return Err(format!(
            "the probe must be between 64 and 128 MiB, not {len} bytes"
        ));
    }
    let options = BackendOptions {
        bundle_dir: PathBuf::from(bundle),
        data_dir: data.clone(),
        headless: true,
        serial_console: true,
        capture_quota_size: 1024 * 1024 * 1024,
        ..Default::default()
    };
    let mut d = Driver {
        backend: Backend::new(options)?,
        snapshot: Snapshot::default(),
        replies: BTreeMap::new(),
        output: BTreeMap::new(),
    };
    let mut t = Table::default();
    let mut errors = Vec::new();
    if let Err(error) = big(&mut d, &mut t, &probe, len, &sha256) {
        errors.push(format!("big: {error}"));
        let _ = d.stop();
    }
    if let Err(error) = small(&mut d, &mut t, &probe) {
        errors.push(format!("small: {error}"));
        let _ = d.stop();
    }
    let _ = d.command(Command::Close, 30);
    let mut failures = t.failures;
    failures.extend(errors);
    if failures.is_empty() {
        println!("SPECIMEN-CHECK PASS");
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")))
    }
}

fn main() {
    // Static analysis runs this program again as its sandboxed worker.
    if let Some(code) = antinomie_monitor_core::analysis::worker_main_if_requested() {
        std::process::exit(code);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.as_slice() {
        [bundle, data, probe] => check(bundle, data, probe),
        _ => {
            eprintln!("usage: specimen-check BUNDLE NEW_DATA_DIR SPECIMEN_PROBE");
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}
